package kafka

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/IBM/sarama"
)

// EventMessage represents the message format for Kafka
type EventMessage struct {
	HostIP         string `json:"host_ip"`
	Region         string `json:"region"`
	NumHypervisors string `json:"num_hypervisors"`
	RegionID       int    `json:"regionId"`
	Token          string `json:"token"`
	CloudProvider  string `json:"cloudProvider"`
	Operation      string `json:"operation"`
}

// Producer represents a Kafka producer
type Producer struct {
	producer sarama.SyncProducer
	topic    string
}

// NewProducer creates a new Kafka producer
func NewProducer(brokerAddr, topic string) (*Producer, error) {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 5
	config.Producer.Return.Successes = true

	producer, err := sarama.NewSyncProducer([]string{brokerAddr}, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create producer: %v", err)
	}

	return &Producer{
		producer: producer,
		topic:    topic,
	}, nil
}

// SendEvent sends an event message to Kafka
func (p *Producer) SendEvent(msg EventMessage) error {
	jsonData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	message := &sarama.ProducerMessage{
		Topic: p.topic,
		Value: sarama.StringEncoder(jsonData),
	}

	partition, offset, err := p.producer.SendMessage(message)
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	log.Printf("Message sent to partition %d at offset %d", partition, offset)
	return nil
}

// Close closes the Kafka producer
func (p *Producer) Close() error {
	return p.producer.Close()
}
