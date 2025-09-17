package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
)

type CacheService struct {
	client *redis.Client
	ctx    context.Context
}

type CacheEntry struct {
	Key         string      `json:"key"`
	Value       interface{} `json:"value"`
	Expiration  time.Time   `json:"expiration"`
	CreatedAt   time.Time   `json:"created_at"`
	AccessCount int64       `json:"access_count"`
	LastAccess  time.Time   `json:"last_access"`
}

type CacheStats struct {
	HitRate     float64 `json:"hit_rate"`
	MissRate    float64 `json:"miss_rate"`
	TotalHits   int64   `json:"total_hits"`
	TotalMisses int64   `json:"total_misses"`
	MemoryUsage int64   `json:"memory_usage"`
	KeyCount    int64   `json:"key_count"`
	Evictions   int64   `json:"evictions"`
}

func NewCacheService() *CacheService {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	client := redis.NewClient(&redis.Options{
		Addr:     redisURL,
		Password: "",
		DB:       0,
	})

	ctx := context.Background()

	// Test connection
	_, err := client.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	return &CacheService{
		client: client,
		ctx:    ctx,
	}
}

func (c *CacheService) Set(key string, value interface{}, expiration time.Duration) error {
	entry := CacheEntry{
		Key:         key,
		Value:       value,
		Expiration:  time.Now().Add(expiration),
		CreatedAt:   time.Now(),
		AccessCount: 0,
		LastAccess:  time.Now(),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return c.client.Set(c.ctx, key, data, expiration).Err()
}

func (c *CacheService) Get(key string) (interface{}, error) {
	data, err := c.client.Get(c.ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Cache miss
		}
		return nil, err
	}

	var entry CacheEntry
	err = json.Unmarshal([]byte(data), &entry)
	if err != nil {
		return nil, err
	}

	// Update access statistics
	entry.AccessCount++
	entry.LastAccess = time.Now()

	// Update entry in cache
	updatedData, _ := json.Marshal(entry)
	c.client.Set(c.ctx, key, updatedData, time.Until(entry.Expiration))

	return entry.Value, nil
}

func (c *CacheService) Delete(key string) error {
	return c.client.Del(c.ctx, key).Err()
}

func (c *CacheService) Exists(key string) bool {
	result, err := c.client.Exists(c.ctx, key).Result()
	return err == nil && result > 0
}

func (c *CacheService) GetStats() (*CacheStats, error) {
	info, err := c.client.Info(c.ctx, "stats").Result()
	if err != nil {
		return nil, err
	}

	// Parse Redis info for statistics
	stats := &CacheStats{
		HitRate:     0.0,
		MissRate:    0.0,
		TotalHits:   0,
		TotalMisses: 0,
		MemoryUsage: 0,
		KeyCount:    0,
		Evictions:   0,
	}

	// Parse info string (simplified)
	// In production, you'd parse the info string properly
	stats.KeyCount, _ = c.client.DBSize(c.ctx).Result()

	return stats, nil
}

func (c *CacheService) Flush() error {
	return c.client.FlushDB(c.ctx).Err()
}

func (c *CacheService) Close() error {
	return c.client.Close()
}

// Advanced caching patterns
func (c *CacheService) GetOrSet(key string, factory func() (interface{}, error), expiration time.Duration) (interface{}, error) {
	// Try to get from cache first
	value, err := c.Get(key)
	if err != nil {
		return nil, err
	}

	if value != nil {
		return value, nil
	}

	// Cache miss - generate value
	value, err = factory()
	if err != nil {
		return nil, err
	}

	// Store in cache
	err = c.Set(key, value, expiration)
	if err != nil {
		log.Printf("Failed to cache value for key %s: %v", key, err)
	}

	return value, nil
}

func (c *CacheService) SetMultiple(entries map[string]interface{}, expiration time.Duration) error {
	pipe := c.client.Pipeline()

	for key, value := range entries {
		entry := CacheEntry{
			Key:         key,
			Value:       value,
			Expiration:  time.Now().Add(expiration),
			CreatedAt:   time.Now(),
			AccessCount: 0,
			LastAccess:  time.Now(),
		}

		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}

		pipe.Set(c.ctx, key, data, expiration)
	}

	_, err := pipe.Exec(c.ctx)
	return err
}

func (c *CacheService) GetMultiple(keys []string) (map[string]interface{}, error) {
	pipe := c.client.Pipeline()

	cmds := make([]*redis.StringCmd, len(keys))
	for i, key := range keys {
		cmds[i] = pipe.Get(c.ctx, key)
	}

	_, err := pipe.Exec(c.ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[string]interface{})
	for i, cmd := range cmds {
		data, err := cmd.Result()
		if err != nil {
			if err != redis.Nil {
				return nil, err
			}
			continue // Cache miss
		}

		var entry CacheEntry
		err = json.Unmarshal([]byte(data), &entry)
		if err != nil {
			return nil, err
		}

		// Update access statistics
		entry.AccessCount++
		entry.LastAccess = time.Now()

		// Update entry in cache
		updatedData, _ := json.Marshal(entry)
		c.client.Set(c.ctx, keys[i], updatedData, time.Until(entry.Expiration))

		result[keys[i]] = entry.Value
	}

	return result, nil
}

// Cache warming and invalidation
func (c *CacheService) WarmCache(keys []string, factory func(string) (interface{}, error), expiration time.Duration) error {
	for _, key := range keys {
		value, err := factory(key)
		if err != nil {
			log.Printf("Failed to warm cache for key %s: %v", key, err)
			continue
		}

		err = c.Set(key, value, expiration)
		if err != nil {
			log.Printf("Failed to set cache for key %s: %v", key, err)
		}
	}

	return nil
}

func (c *CacheService) InvalidatePattern(pattern string) error {
	keys, err := c.client.Keys(c.ctx, pattern).Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return c.client.Del(c.ctx, keys...).Err()
	}

	return nil
}

// Cache health check
func (c *CacheService) HealthCheck() error {
	_, err := c.client.Ping(c.ctx).Result()
	return err
}
