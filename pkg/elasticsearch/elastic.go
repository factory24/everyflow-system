package elasticsearchClient

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
)

type ElasticSearchClient interface {
	IndexMultipleDocuments(indexName string, data interface{}) error
	Connect()
	IndexSingleDocument(indexName string, documentID string, data interface{}) error
	UpdateDocument(indexName string, documentID string, updateData interface{}) error
	DeleteDocument(indexName string, documentID string) error
	SearchDocuments(indexName string, query map[string]interface{}) ([]interface{}, int64, error)
	FieldSearchDocuments(indexName string, query map[string]interface{}) ([]interface{}, int64, error)
	DeleteIndex(indexName string) error
	AggregateDocuments(indexName string, aggregations map[string]interface{}, query map[string]interface{}) (*AggregationResults, error)
	Bulk(indexName string, documents []interface{}) error
}

type elasticSearchClient struct {
	es *elasticsearch.Client
}

func (service *elasticSearchClient) DeleteIndex(indexName string) error {
	res, err := service.es.Indices.Delete([]string{indexName})
	if err != nil {
		return fmt.Errorf("cannot delete index: %w", err)
	}
	defer res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("cannot delete index: %s", res.String())
	}
	return nil
}

func (service *elasticSearchClient) IndexMultipleDocuments(indexName string, data interface{}) error {
	// Use reflection to handle different data types
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Slice {
		return fmt.Errorf("expected a slice, got %v", val.Kind())
	}

	documents := make([]interface{}, val.Len())
	for i := 0; i < val.Len(); i++ {
		documents[i] = val.Index(i).Interface()
	}

	return service.Bulk(indexName, documents)
}

func (service *elasticSearchClient) Bulk(indexName string, documents []interface{}) error {
	if len(documents) == 0 {
		return nil
	}

	var batch []string
	for _, doc := range documents {
		meta := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": indexName,
			},
		}

		// If the document has an ID field (via reflection)
		val := reflect.ValueOf(doc)
		if val.Kind() == reflect.Ptr {
			val = val.Elem()
		}
		if val.Kind() == reflect.Struct {
			idField := val.FieldByName("ID")
			if idField.IsValid() && idField.Kind() == reflect.String && idField.String() != "" {
				meta["index"].(map[string]interface{})["_id"] = idField.String()
			}
		}

		metaJSON, _ := json.Marshal(meta)
		docJSON, err := json.Marshal(doc)
		if err != nil {
			log.Printf("failed to marshal document: %v", err)
			continue
		}

		batch = append(batch, string(metaJSON), string(docJSON))
	}

	body := strings.Join(batch, "\n") + "\n"
	res, err := service.es.Bulk(strings.NewReader(body), service.es.Bulk.WithIndex(indexName))
	if err != nil {
		return fmt.Errorf("bulk index request failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("bulk index error: %s", res.String())
	}

	return nil
}

func (service *elasticSearchClient) IndexSingleDocument(indexName string, documentID string, data interface{}) error {
	// Convert the data to JSON
	itemJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data to JSON: %w", err)
	}

	// Index the document in Elasticsearch
	res, err := service.es.Index(
		indexName,                                   // Index name
		strings.NewReader(string(itemJSON)),         // Document body
		service.es.Index.WithDocumentID(documentID), // Optional: specify a document ID
	)
	if err != nil {
		return fmt.Errorf("failed to index document in Elasticsearch: %w", err)
	}
	defer res.Body.Close()

	// Check for errors in the Elasticsearch response
	if res.IsError() {
		var e map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			return fmt.Errorf("failed to parse Elasticsearch error response: %w", err)
		}
		return fmt.Errorf("Elasticsearch error: %s", e["error"].(map[string]interface{})["reason"])
	}

	return nil
}

func (service *elasticSearchClient) UpdateDocument(indexName string, documentID string, updateData interface{}) error {
	// Convert the update data to JSON
	updateJSON, err := json.Marshal(updateData)
	if err != nil {
		return fmt.Errorf("failed to marshal update data to JSON: %w", err)
	}

	// Update the document in Elasticsearch
	res, err := service.es.Update(
		indexName,                             // Index name
		documentID,                            // Document ID
		strings.NewReader(string(updateJSON)), // Update body
	)
	if err != nil {
		return fmt.Errorf("failed to update document in Elasticsearch: %w", err)
	}
	defer res.Body.Close()

	// Check for errors in the Elasticsearch response
	if res.IsError() {
		var e map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			return fmt.Errorf("failed to parse Elasticsearch error response: %w", err)
		}
		return fmt.Errorf("Elasticsearch error: %s", e["error"].(map[string]interface{})["reason"])
	}

	return nil
}

func (service *elasticSearchClient) DeleteDocument(indexName string, documentID string) error {
	// Delete the document in Elasticsearch
	res, err := service.es.Delete(
		indexName,  // Index name
		documentID, // Document ID
	)
	if err != nil {
		return fmt.Errorf("failed to delete document in Elasticsearch: %w", err)
	}
	defer res.Body.Close()

	// Check for errors in the Elasticsearch response
	if res.IsError() {
		var e map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			return fmt.Errorf("failed to parse Elasticsearch error response: %w", err)
		}
		return fmt.Errorf("Elasticsearch error: %s", e["error"].(map[string]interface{})["reason"])
	}

	return nil
}

func (service *elasticSearchClient) SearchDocuments(indexName string, query map[string]interface{}) ([]interface{}, int64, error) {
	// Convert the query to JSON
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal query to JSON: %w", err)
	}

	log.Printf("Elasticsearch Query for index %s: %s", indexName, queryJSON)

	// Perform the search in Elasticsearch
	res, err := service.es.Search(
		service.es.Search.WithIndex(indexName),                           // Index name
		service.es.Search.WithBody(strings.NewReader(string(queryJSON))), // Query body
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search documents in Elasticsearch: %w", err)
	}
	defer res.Body.Close()

	// Check for errors in the Elasticsearch response
	if res.IsError() {
		var e map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			return nil, 0, fmt.Errorf("failed to parse Elasticsearch error response: %w", err)
		}
		return nil, 0, fmt.Errorf("Elasticsearch error: %s", e["error"].(map[string]interface{})["reason"])
	}

	// Parse the search results
	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("failed to parse search results: %w", err)
	}
	hitsTotalValue := int64(0) // Default to 0 if total is not found or is not a number
	hitsTotal, ok := result["hits"].(map[string]interface{})["total"].(map[string]interface{})
	if ok {
		totalValue, ok := hitsTotal["value"].(float64) // Total hits value is often returned as float64
		if ok {
			hitsTotalValue = int64(totalValue) // Convert float64 to int64
		}
	}

	// Extract the hits from the search results
	hits := result["hits"].(map[string]interface{})["hits"].([]interface{})
	var documents []interface{}
	for _, hit := range hits {
		documents = append(documents, hit.(map[string]interface{})["_source"])
	}

	return documents, hitsTotalValue, nil
}

func (service *elasticSearchClient) FieldSearchDocuments(indexName string, query map[string]interface{}) ([]interface{}, int64, error) {
	// Convert the query to JSON
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal query to JSON: %w", err)
	}

	log.Printf("Elasticsearch Query for index %s: %s", indexName, queryJSON)

	// Perform the search in Elasticsearch
	res, err := service.es.Search(
		service.es.Search.WithIndex(indexName),                           // Index name
		service.es.Search.WithBody(strings.NewReader(string(queryJSON))), // Query body
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search documents in Elasticsearch: %w", err)
	}
	defer res.Body.Close()

	// Check for errors in the Elasticsearch response
	if res.IsError() {
		var e map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			return nil, 0, fmt.Errorf("failed to parse Elasticsearch error response: %w", err)
		}
		return nil, 0, fmt.Errorf("Elasticsearch error: %s", e["error"].(map[string]interface{})["reason"])
	}

	// Parse the search results
	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("failed to parse search results: %w", err)
	}
	hitsTotalValue := int64(0) // Default to 0 if total is not found or is not a number
	hitsTotal, ok := result["hits"].(map[string]interface{})["total"].(map[string]interface{})
	if ok {
		totalValue, ok := hitsTotal["value"].(float64) // Total hits value is often returned as float64
		if ok {
			hitsTotalValue = int64(totalValue) // Convert float64 to int64
		}
	}

	// Extract the hits from the search results
	hits := result["hits"].(map[string]interface{})["hits"].([]interface{})
	var documents []interface{}
	for _, hit := range hits {
		documents = append(documents, hit.(map[string]interface{})["fields"])
	}

	return documents, hitsTotalValue, nil
}

// AggregateDocuments performs an aggregation query in Elasticsearch.
func (service *elasticSearchClient) AggregateDocuments(indexName string, aggregations map[string]interface{}, query map[string]interface{}) (*AggregationResults, error) {
	// Convert the aggregations map to JSON
	aggsJSON, err := json.Marshal(aggregations)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal aggregations to JSON: %w", err)
	}

	// Convert the query to JSON
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query to JSON: %w", err)
	}

	// Perform the aggregation search in Elasticsearch
	queryBody := fmt.Sprintf(`{"aggs": %s, "size": 0, "query": %s, "track_total_hits": true}`, aggsJSON, queryJSON)

	log.Printf("Elasticsearch Query for index %s: %s", indexName, queryBody)

	res, err := service.es.Search(
		service.es.Search.WithIndex(indexName),                   // Index name
		service.es.Search.WithSize(0),                            // Set size to 0 as we only want aggregations, not hits
		service.es.Search.WithBody(strings.NewReader(queryBody)), // Aggregations body
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute aggregation in Elasticsearch: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Printf("failed to close response body in Elasticsearch: %v", err)
		}
	}(res.Body)

	// Check for errors in the Elasticsearch response
	if res.IsError() {
		log.Println("there is an err::")
		var e map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			return nil, fmt.Errorf("failed to parse Elasticsearch error response: %w", err)
		}
		log.Println("Elasticsearch error:", e["error"].(map[string]interface{})["reason"])
		return nil, fmt.Errorf("elasticsearch error during aggregation: %s", e["error"])
	}

	// Parse the aggregation results
	var result *AggregationResults
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse aggregation results: %w", err)
	}

	return result, nil
}

func (service *elasticSearchClient) Connect() {
	log.Println("connecting to elastic search....")
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Elasticsearch client configuration
	cfg := elasticsearch.Config{
		Addresses: []string{
			os.Getenv("ES.URL"),
		},
		APIKey: os.Getenv("ES.KEY"),

		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("Error creating the client: %s", err)
	}

	log.Println("Successfully connected to elastic cluster")
	service.es = es
}

func NewElasticSearchClient() ElasticSearchClient {
	return &elasticSearchClient{}
}
