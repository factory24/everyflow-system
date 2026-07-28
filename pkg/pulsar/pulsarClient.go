package pulsarClient

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	sysResponse "github.com/factory24/flow-system/pkg/response"

	"github.com/apache/pulsar-client-go/pulsar"
	"github.com/apache/pulsar-client-go/pulsar/crypto"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// tracer uses whatever TracerProvider athari-thirdparty/tracing.Connect()
// already registered globally in this service — no separate wiring needed
// per caller. Messaging semantic conventions (messaging.system,
// messaging.destination.name, messaging.operation) are what power SigNoz's
// (and Jaeger's) "Messaging Queues" view; without them a queue is
// functionally invisible there even though traces/spans exist elsewhere.
var tracer = otel.Tracer("pulsar")

const (
	maxPublishRetries = 5
)

type EventHeader = sysResponse.EventHeader

type EventHandler interface {
	HandleEvent(header *EventHeader) error
}

type PulsarClient interface {
	PublishEvent(topic, eventType string, payload any) error
	ListenOnTopics(topics []string, subscriptionName string, handler EventHandler) error
	GetTopics() []string
	Connect()
	// ProcessDLQMessages reprocesses messages from DLQ to target topic
	ProcessDLQMessages(dlqTopic, targetTopic string, maxMessages int) (int, error)
	// GetOrCreateProducer returns a producer for a given topic
	GetOrCreateProducer(topic string) (pulsar.Producer, error)
}

type pulsarClient struct {
	client    pulsar.Client
	producers map[string]pulsar.Producer
	mu        sync.RWMutex
	url       string
	keyReader crypto.KeyReader
	encKeys   []string
}

func NewPulsarClient() PulsarClient {
	return &pulsarClient{
		producers: make(map[string]pulsar.Producer),
	}
}

func newStringKeyReader(pubKeyStr, privKeyStr string) (crypto.KeyReader, error) {
	pubKeyStr = strings.ReplaceAll(pubKeyStr, `\n`, "\n")
	privKeyStr = strings.ReplaceAll(privKeyStr, `\n`, "\n")

	PulsarLogInfo("Public Key (first 20 chars): %s", pubKeyStr[:20])
	PulsarLogInfo("Public Key (last 20 chars): %s", pubKeyStr[len(pubKeyStr)-20:])
	PulsarLogInfo("Private Key (first 20 chars): %s", privKeyStr[:20])
	PulsarLogInfo("Private Key (last 20 chars): %s", privKeyStr[len(privKeyStr)-20:])

	// Log the length of the key strings for debugging
	fmt.Printf("Public Key Length: %d\n", len(pubKeyStr))
	fmt.Printf("Private Key Length: %d\n", len(privKeyStr))

	pubBlock, _ := pem.Decode([]byte(pubKeyStr))
	if pubBlock == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}
	if _, err := x509.ParsePKIXPublicKey(pubBlock.Bytes); err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	privBlock, _ := pem.Decode([]byte(privKeyStr))
	if privBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	// Parse as PKCS#8
	privKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key as PKCS#8: %w", err)
	}
	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}

	// Marshal to PKCS#1 PEM
	pkcs1Bytes := x509.MarshalPKCS1PrivateKey(rsaPrivKey)
	pkcs1Pem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs1Bytes,
	})

	tmpPubFile := filepath.Join(os.TempDir(), "pulsar_pub.pem")
	tmpPrivFile := filepath.Join(os.TempDir(), "pulsar_priv.pem")
	if err := os.WriteFile(tmpPubFile, []byte(pubKeyStr), 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(tmpPrivFile, pkcs1Pem, 0600); err != nil { // Write PKCS#1 PEM
		return nil, err
	}

	return crypto.NewFileKeyReader(tmpPubFile, tmpPrivFile), nil
}

func (p *pulsarClient) Connect() {
	if p.client != nil {
		return
	}

	p.url = os.Getenv("PULSAR.URL")
	if p.url == "" {
		log.Fatal("PULSAR.URL environment variable not set")
	}

	pubKeyStr := os.Getenv("PULSAR.PUBKEY")
	privKeyStr := os.Getenv("PULSAR.PRIVKEY")
	encKeyName := os.Getenv("PULSAR.ENCRYPTION.KEY")

	if pubKeyStr != "" && privKeyStr != "" && encKeyName != "" {
		keyReader, err := newStringKeyReader(pubKeyStr, privKeyStr)
		if err != nil {
			log.Fatalf("failed to create key reader: %v", err)
		}
		p.keyReader = keyReader
		p.encKeys = []string{encKeyName}
		PulsarLogSuccess("String-based key reader created.")
	} else {
		PulsarLogInfo("Pulsar encryption keys not set, encryption will be disabled.")
	}

	client, err := pulsar.NewClient(pulsar.ClientOptions{
		URL:               p.url,
		OperationTimeout:  30 * time.Second,
		ConnectionTimeout: 30 * time.Second,
	})
	if err != nil {
		log.Fatalf("could not create pulsar client: %v", err)
	}
	p.client = client
	PulsarLogSuccess("Client connected successfully to %s", p.url)
}

func (p *pulsarClient) GetTopics() []string {
	pulsarTopics := os.Getenv("EVENT_TOPICS")
	if pulsarTopics == "" {
		log.Fatal("EVENT_TOPIC environment variable not set")
	}
	topicStrings := strings.Split(pulsarTopics, ",")
	var topics []string
	for _, t := range topicStrings {
		if trimmed := strings.TrimSpace(t); trimmed != "" {
			topics = append(topics, trimmed)
		}
	}
	if len(topics) == 0 {
		log.Fatal("No topics found in EVENT_TOPIC")
	}
	return topics
}

func (p *pulsarClient) ListenOnTopics(topics []string, subscriptionName string, handler EventHandler) error {
	for _, topic := range topics {
		dlqTopic := topic + ".dead_letter"

		serviceName := os.Getenv("APP.SERVICE.NAME")
		if serviceName == "" {
			return fmt.Errorf("APP.SERVICE.NAME environment variable not set")
		}

		rand.Seed(time.Now().UnixNano())
		consumerName := fmt.Sprintf("%s-consumer-%02d", serviceName, rand.Intn(100))

		channel := make(chan pulsar.ConsumerMessage, 2000)

		consumerOptions := pulsar.ConsumerOptions{
			Topics:           topics,
			SubscriptionName: subscriptionName,
			Type:             pulsar.Shared,
			Name:             consumerName,
			MessageChannel:   channel,
			DLQ: &pulsar.DLQPolicy{
				MaxDeliveries:           10,
				DeadLetterTopic:         dlqTopic,
				InitialSubscriptionName: subscriptionName,
			},
			Decryption: &pulsar.MessageDecryptionInfo{
				KeyReader:                   p.keyReader,
				MessageCrypto:               nil,
				ConsumerCryptoFailureAction: 1,
			},
		}

		consumer, err := p.client.Subscribe(consumerOptions)
		if err != nil {
			return fmt.Errorf("could not subscribe to topic %s: %w", topic, err)
		}

		workerCount := 20
		for i := 0; i < workerCount; i++ {
			go func(topic string, ch <-chan pulsar.ConsumerMessage, consumer pulsar.Consumer) {
				defer consumer.Close()
				for {
					select {
					case cm, ok := <-ch:
						if !ok {
							PulsarLogError("errorr")

							return
						}

						p.processMessage(cm.Message, handler, consumer, topic+".dead_letter")

					case <-context.Background().Done():
						return
					}
				}
			}(topic, channel, consumer)
		}
	}
	return nil
}

func (p *pulsarClient) processMessage(msg pulsar.Message, handler EventHandler, consumer pulsar.Consumer, dlqTopic string) {
	// Join the producer's trace (see PublishEvent) via the properties it was
	// injected into, rather than starting an unrelated one — properties are
	// Pulsar's closest equivalent to HTTP headers for propagation, since it
	// has no native trace-context field.
	carrier := propagation.MapCarrier(msg.Properties())
	parentCtx := otel.GetTextMapPropagator().Extract(context.Background(), carrier)

	// EventHandler.HandleEvent takes no context.Context (interface change
	// would ripple across every handler in every service), so this span
	// can't be threaded further into the handler — it still captures the
	// message-processing duration/outcome itself, linked to the producer.
	_, span := tracer.Start(parentCtx, msg.Topic()+" process",
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.String("messaging.system", "pulsar"),
			attribute.String("messaging.destination.name", msg.Topic()),
			attribute.String("messaging.operation", "process"),
			attribute.String("messaging.message.id", msg.ID().String()),
		),
	)
	defer span.End()

	header, err := sysResponse.ParseEventHeader(msg.Payload())
	if err != nil {
		PulsarLogError("Failed to parse event header for message %v: %v", msg.ID(), err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "unparseable payload")
		if dlqTopic != "" {
			PulsarLogError("Sending unparseable message %v to DLQ topic: %s", msg.ID(), dlqTopic)
			if dlqErr := p.sendToDLQ(dlqTopic, msg, "unparseable_payload", err.Error()); dlqErr != nil {
				PulsarLogError("CRITICAL: Failed to send message %v to DLQ: %v. Nacking.", msg.ID(), dlqErr)
				consumer.Nack(msg)
				return
			}
		}
		consumer.Ack(msg)
		return
	}

	span.SetAttributes(attribute.String("messaging.pulsar.event_type", header.EventType))

	header.PrettyLog()
	if err := handler.HandleEvent(header); err != nil {
		PulsarLogError("Handler failed to process event '%s' (ID: %v): %v. Nacking message.", header.EventType, msg.ID(), err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		consumer.Nack(msg)
	} else {
		PulsarLogSuccess("Successfully processed event '%s' (ID: %v)", header.EventType, msg.ID())
		consumer.Ack(msg)
	}
}

func (p *pulsarClient) sendToDLQ(dlqTopic string, originalMsg pulsar.Message, reason, errorDetail string) error {
	producer, err := p.GetOrCreateProducer(dlqTopic)
	if err != nil {
		return fmt.Errorf("failed to get producer for DLQ topic %s: %w", dlqTopic, err)
	}

	properties := map[string]string{
		"dlq_reason":          reason,
		"dlq_error_detail":    errorDetail,
		"original_topic":      originalMsg.Topic(),
		"original_message_id": originalMsg.ID().String(),
	}
	for k, v := range originalMsg.Properties() {
		properties["original_prop_"+k] = v
	}

	_, err = producer.Send(context.Background(), &pulsar.ProducerMessage{
		Payload:    originalMsg.Payload(),
		Properties: properties,
	})
	if err != nil {
		p.mu.Lock()
		producer.Close()
		delete(p.producers, dlqTopic)
		p.mu.Unlock()
		return fmt.Errorf("failed to publish message to DLQ topic %s: %w", dlqTopic, err)
	}
	return nil
}

// PublishEvent has no context.Context parameter (a signature change would
// touch every call site across every service), so this span can't link back
// to whatever caller/HTTP-handler span triggered the publish — it starts a
// new trace rooted at the publish itself. It still gives the consumer side
// something to link to (trace context is injected into message properties
// below), and gives SigNoz/Jaeger's Messaging Queues view real publish
// spans with proper messaging.* attributes, which is what was missing
// entirely before this.
func (p *pulsarClient) PublishEvent(topic, eventType string, payload any) error {
	ctx, span := tracer.Start(context.Background(), topic+" send",
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			attribute.String("messaging.system", "pulsar"),
			attribute.String("messaging.destination.name", topic),
			attribute.String("messaging.operation", "publish"),
			attribute.String("messaging.pulsar.event_type", eventType),
		),
	)
	defer span.End()

	producer, err := p.GetOrCreateProducer(topic)
	if err != nil {
		PulsarLogError("failed to get producer for topic %s: %v", topic, err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to get producer for topic %s: %w", topic, err)
	}

	event := sysResponse.NewEvent(topic, eventType, payload)
	payloadBytes, err := event.Bytes()
	if err != nil {
		PulsarLogError("failed to marshal event: %w", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Carries this span's context to the consumer via message properties —
	// Pulsar has no native trace-context header, so properties are the
	// closest equivalent to how OTel HTTP propagation uses headers.
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)

	for i := 0; i <= maxPublishRetries; i++ {
		_, err = producer.Send(ctx, &pulsar.ProducerMessage{
			Payload:    payloadBytes,
			Properties: carrier,
		})
		if err == nil {
			PulsarLogInfo("Published event '%s' to topic '%s'", eventType, topic)
			return nil // Success
		}

		PulsarLogError("Failed to publish event to topic %s (attempt %d/%d): %w", topic, i+1, maxPublishRetries+1, err)

		// If it's the last retry, or a non-recoverable error, break
		if i == maxPublishRetries {
			break
		}

		// Close and delete producer on error to force recreation on next retry
		p.mu.Lock()
		producer.Close()
		delete(p.producers, topic)
		p.mu.Unlock()

		time.Sleep(time.Second)                      // Delay before next retry
		producer, err = p.GetOrCreateProducer(topic) // Get a new producer for retry
		if err != nil {
			PulsarLogError("Failed to get producer for topic %s on retry (attempt %d/%d): %v", topic, i+1, maxPublishRetries+1, err.Error())
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return fmt.Errorf("failed to get producer for topic %s on retry: %w", topic, err)
		}
	}

	// If we reach here, all retries failed
	PulsarLogError("All %d retries failed for event to topic %s: %w", maxPublishRetries+1, topic, err)
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
	return fmt.Errorf("all %d retries failed to publish event to topic %s: %w", maxPublishRetries+1, topic, err)
}

func (p *pulsarClient) GetOrCreateProducer(topic string) (pulsar.Producer, error) {
	p.mu.RLock()
	producer, found := p.producers[topic]
	p.mu.RUnlock()
	if found {
		return producer, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if producer, found = p.producers[topic]; found {
		return producer, nil
	}

	serviceName := os.Getenv("APP.SERVICE.NAME")
	if serviceName == "" {
		return nil, fmt.Errorf("APP.SERVICE.NAME environment variable not set")
	}

	rand.Seed(time.Now().UnixNano())
	producerName := fmt.Sprintf("%s-producer-%02d", serviceName, rand.Intn(100))
	PulsarLogSuccess("Producer name ::::: %s", producerName)

	PulsarLogInfo("Creating new producer for topic: %s with name: %s", topic, producerName)
	newProducer, err := p.client.CreateProducer(pulsar.ProducerOptions{
		Topic:           topic,
		DisableBatching: false,
		Name:            producerName,
		Encryption: &pulsar.ProducerEncryptionInfo{
			KeyReader: p.keyReader,
			Keys:      p.encKeys,
		},
		SendTimeout: 30 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	p.producers[topic] = newProducer
	return newProducer, nil
}

// ProcessDLQMessages consumes messages from the DLQ (dlqTopic) and republishes them to the original topic (targetTopic).
// It processes up to maxMessages, or until the DLQ is empty (retrieving with a short timeout).
// It returns the number of messages successfully reprocessed.
func (p *pulsarClient) ProcessDLQMessages(dlqTopic, targetTopic string, maxMessages int) (int, error) {
	// Create a reader or consumer for the DLQ. A Reader is often better for "replaying" or batch processing exact messages,
	// but a Consumer is standard if we want to acknowledge them as we handle them.
	// Using a Consumer with shared subscription to drain the DLQ.

	serviceName := os.Getenv("APP.SERVICE.NAME")
	if serviceName == "" {
		return 0, fmt.Errorf("APP.SERVICE.NAME environment variable not set")
	}
	subscriptionName := fmt.Sprintf("%s-dlq-processor", serviceName)

	channel := make(chan pulsar.ConsumerMessage, 100)
	// dlqTopic string, originalMsg pulsar.Message, reason, errorDetail string
	consumerOptions := pulsar.ConsumerOptions{
		Topics:           []string{dlqTopic},
		SubscriptionName: subscriptionName,
		Type:             pulsar.Shared,
		MessageChannel:   channel,
		Decryption: &pulsar.MessageDecryptionInfo{
			KeyReader:                   p.keyReader,
			MessageCrypto:               nil,
			ConsumerCryptoFailureAction: 1,
		},
	}

	consumer, err := p.client.Subscribe(consumerOptions)
	if err != nil {
		return 0, fmt.Errorf("failed to subscribe to DLQ topic %s: %w", dlqTopic, err)
	}
	defer consumer.Close()

	processedCount := 0

	// We'll try to read up to maxMessages.
	// Since we are using a channel, we can perform a loop with a timeout/select.
	// But `Subscribe` runs asynchronously. We might want to just loop `maxMessages` times.

	PulsarLogInfo("Starting processing of DLQ messages from %s to %s", dlqTopic, targetTopic)

	for i := 0; i < maxMessages; i++ {
		select {
		case cm := <-channel:
			msg := cm.Message
			// Republish to target topic
			// We might want to construct a new wrapper or just send the payload.
			// The test implies we just want to move them back.

			// Note: In a real scenario, you might check properties "dlq_reason" etc.
			// Here we just blindly republish.

			PulsarLogInfo("Reprocessing message %v from DLQ", msg.ID())

			// Use PublishEvent if it's a standard event structure?
			// PublishEvent assumes a payload structure and marshals it.
			// The message payload is already bytes. We should probably use the low-level producer directly
			// to preserve the payload exactly as is (it might be raw bytes if it failed parsing).

			producer, err := p.GetOrCreateProducer(targetTopic)
			if err != nil {
				PulsarLogError("Failed to get producer for target topic %s: %v", targetTopic, err)
				consumer.Nack(msg)
				continue
			}

			// Forward the message
			_, err = producer.Send(context.Background(), &pulsar.ProducerMessage{
				Payload: msg.Payload(),
				// Preserve original properties? Or add new ones?
				// Let's copy properties but maybe update some timestamps if needed.
				Properties: msg.Properties(),
			})

			if err != nil {
				PulsarLogError("Failed to republish message %v: %v", msg.ID(), err)
				consumer.Nack(msg)
			} else {
				PulsarLogSuccess("Republished message %v to %s", msg.ID(), targetTopic)
				consumer.Ack(msg)
				processedCount++
			}

		case <-time.After(5 * time.Second):
			// Timeout if no messages are available in DLQ
			PulsarLogInfo("Timeout waiting for DLQ messages (processed %d so far)", processedCount)
			return processedCount, nil
		}
	}

	return processedCount, nil
}
