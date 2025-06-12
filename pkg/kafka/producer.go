package kafka

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/IBM/sarama"
)

// EventMessage represents the message structure for Kafka events
type EventMessage struct {
	InstanceID  string    `json:"instance_id"`
	PrivateIP   string    `json:"private_ip"`
	DisplayName string    `json:"display_name"`
	Token       string    `json:"token"`
	Timestamp   time.Time `json:"timestamp"`
}

// Producer handles Kafka message production
type Producer struct {
	producer sarama.SyncProducer
	topic    string
}

// NewProducer creates a new Kafka producer
func NewProducer(brokerAddr, topic string) (*Producer, error) {
	log.Printf("Configuring Kafka producer")
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 5
	config.Producer.Return.Successes = true
	config.Producer.Timeout = 5 * time.Second

	// Add version configuration
	config.Version = sarama.V2_8_1_0
	log.Printf("Using Kafka version: %s", config.Version)

	// Add broker configuration
	brokers := []string{brokerAddr}
	log.Printf("Attempting to connect to Kafka brokers: %v", brokers)

	// Create producer with timeout
	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		log.Printf("Failed to create Kafka producer: %v", err)
		return nil, fmt.Errorf("failed to create Kafka producer: %v", err)
	}

	log.Printf("Successfully connected to Kafka broker")
	return &Producer{
		producer: producer,
		topic:    topic,
	}, nil
}

// SendEvent sends an event message to Kafka
func (p *Producer) SendEvent(msg EventMessage) error {
	log.Printf("Preparing to send message to topic %s", p.topic)

	// Marshal message to JSON
	jsonData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	// Create Kafka message
	kafkaMsg := &sarama.ProducerMessage{
		Topic: p.topic,
		Value: sarama.StringEncoder(jsonData),
	}

	log.Printf("Sending message to Kafka: %s", string(jsonData))
	_, _, err = p.producer.SendMessage(kafkaMsg)
	if err != nil {
		return fmt.Errorf("failed to send message to Kafka: %v", err)
	}

	log.Printf("Successfully sent message to Kafka")
	return nil
}

// Close closes the Kafka producer
func (p *Producer) Close() error {
	log.Printf("Closing Kafka producer")
	return p.producer.Close()
}
