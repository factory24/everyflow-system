package elasticsearchClient

import "encoding/json"

// AggregationResults represents the full Elasticsearch aggregation response.
type AggregationResults struct {
	Took         int             `json:"took"`
	TimedOut     bool            `json:"timed_out"`
	Shards       Shards          `json:"_shards"`
	Hits         *Hits           `json:"hits"`
	Aggregations json.RawMessage `json:"aggregations"`
}

// UnmarshalAggregations unmarshals the raw aggregations JSON into a typed struct.
func (r *AggregationResults) UnmarshalAggregations(target interface{}) error {
	if r.Aggregations == nil {
		return nil
	}
	return json.Unmarshal(r.Aggregations, target)
}

// GetAggregationsMap returns aggregations as a generic map for dynamic key access.
func (r *AggregationResults) GetAggregationsMap() (map[string]interface{}, error) {
	if r.Aggregations == nil {
		return nil, nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(r.Aggregations, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Shards represents the _shards section of an Elasticsearch response.
type Shards struct {
	Total      int `json:"total"`
	Successful int `json:"successful"`
	Skipped    int `json:"skipped"`
	Failed     int `json:"failed"`
}

// Hits represents the hits section of an Elasticsearch response.
type Hits struct {
	Total    Total         `json:"total"`
	MaxScore float64       `json:"max_score"`
	Hits     []interface{} `json:"hits"`
}

// Total represents the total hits information.
type Total struct {
	Value    int64  `json:"value"`
	Relation string `json:"relation"`
}

// TermsBucket represents a bucket in a terms aggregation.
type TermsBucket struct {
	Key      interface{} `json:"key"`
	DocCount int64       `json:"doc_count"`
}

// FilterAggregation represents a filter aggregation result.
type FilterAggregation struct {
	DocCount int64 `json:"doc_count"`
}

// ValueCountAggregation represents a value_count aggregation result.
type ValueCountAggregation struct {
	Value int64 `json:"value"`
}
