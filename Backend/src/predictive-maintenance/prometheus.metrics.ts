// src/predictive-maintenance/prometheus.metrics.ts
import { register, Gauge, Counter, Histogram } from 'prom-client';

// System Health Metrics
export const systemHealthStatus = new Gauge({
  name: 'stellara_predictive_health_status',
  help: 'Overall system health status (0=critical, 1=warning, 2=healthy)',
  labelNames: ['component'],
});

// System Metrics
export const cpuUsage = new Gauge({
  name: 'stellara_system_cpu_usage',
  help: 'Current CPU usage percentage',
});

export const memoryUsage = new Gauge({
  name: 'stellara_system_memory_usage',
  help: 'Current memory usage percentage',
});

export const diskUsage = new Gauge({
  name: 'stellara_system_disk_usage',
  help: 'Current disk usage percentage',
});

export const connectionPoolUsage = new Gauge({
  name: 'stellara_system_connection_pool_usage',
  help: 'Current connection pool usage percentage',
});

// Prediction Metrics
export const activePredictions = new Gauge({
  name: 'stellara_predictive_active_predictions',
  help: 'Number of active predictions',
  labelNames: ['type', 'risk_level'],
});

export const predictionConfidence = new Histogram({
  name: 'stellara_predictive_confidence',
  help: 'Distribution of prediction confidence scores',
  buckets: [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
});

export const riskLevelCounts = new Gauge({
  name: 'stellara_predictive_risk_level',
  help: 'Count of predictions by risk level',
  labelNames: ['risk'],
});

// Anomaly Detection Metrics
export const anomalyCount = new Counter({
  name: 'stellara_predictive_anomalies_total',
  help: 'Total number of anomalies detected',
  labelNames: ['metric_type', 'severity'],
});

export const anomalyDetectionTime = new Histogram({
  name: 'stellara_predictive_anomaly_detection_duration',
  help: 'Time taken to detect anomalies',
  buckets: [0.1, 0.5, 1, 2, 5, 10],
});

// Capacity Forecasting Metrics
export const capacityForecastDays = new Gauge({
  name: 'stellara_capacity_forecast_days_remaining',
  help: 'Days remaining until capacity threshold',
  labelNames: ['resource_type'],
});

export const capacityForecastAccuracy = new Histogram({
  name: 'stellara_capacity_forecast_accuracy',
  help: 'Accuracy of capacity forecasts',
  buckets: [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
});

// Maintenance Metrics
export const maintenanceTicketsCreated = new Counter({
  name: 'stellara_maintenance_tickets_created_total',
  help: 'Total number of maintenance tickets created',
  labelNames: ['priority', 'auto_generated'],
});

export const maintenanceTicketsResolved = new Counter({
  name: 'stellara_maintenance_tickets_resolved_total',
  help: 'Total number of maintenance tickets resolved',
  labelNames: ['resolution_time_hours'],
});

// Notification Metrics
export const notificationsSent = new Counter({
  name: 'stellara_notifications_sent_total',
  help: 'Total number of notifications sent',
  labelNames: ['channel', 'status'],
});

export const notificationLatency = new Histogram({
  name: 'stellara_notification_send_duration',
  help: 'Time taken to send notifications',
  labelNames: ['channel'],
  buckets: [0.1, 0.5, 1, 2, 5, 10],
});

// ML Model Metrics
export const mlModelAccuracy = new Gauge({
  name: 'stellara_ml_model_accuracy',
  help: 'Current ML model accuracy',
  labelNames: ['model_type', 'version'],
});

export const mlModelTrainingTime = new Histogram({
  name: 'stellara_ml_model_training_duration',
  help: 'Time taken to train ML models',
  buckets: [1, 5, 10, 30, 60, 300],
});

export const mlModelPredictionTime = new Histogram({
  name: 'stellara_ml_model_prediction_duration',
  help: 'Time taken for ML predictions',
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
});

// Performance Metrics
export const serviceUptime = new Counter({
  name: 'stellara_predictive_service_uptime_seconds',
  help: 'Service uptime in seconds',
});

export const metricCollectionDuration = new Histogram({
  name: 'stellara_metric_collection_duration',
  help: 'Time taken to collect system metrics',
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2],
});

export const predictionGenerationDuration = new Histogram({
  name: 'stellara_prediction_generation_duration',
  help: 'Time taken to generate predictions',
  buckets: [0.1, 0.5, 1, 2, 5, 10, 30],
});

// Error Metrics
export const predictionErrors = new Counter({
  name: 'stellara_predictive_errors_total',
  help: 'Total number of prediction errors',
  labelNames: ['error_type'],
});

export const metricCollectionErrors = new Counter({
  name: 'stellara_metric_collection_errors_total',
  help: 'Total number of metric collection errors',
  labelNames: ['metric_type'],
});

// Helper function to update health status
export function updateHealthStatus(component: string, status: 'healthy' | 'warning' | 'critical') {
  const statusValue = status === 'healthy' ? 2 : status === 'warning' ? 1 : 0;
  systemHealthStatus.set({ component }, statusValue);
}

// Helper function to update system metrics
export function updateSystemMetrics(metrics: {
  cpu: number;
  memory: number;
  disk: number;
  connections: number;
}) {
  cpuUsage.set(metrics.cpu);
  memoryUsage.set(metrics.memory);
  diskUsage.set(metrics.disk);
  connectionPoolUsage.set(metrics.connections);
}

// Helper function to update prediction metrics
export function updatePredictionMetrics(predictions: Array<{
  type: string;
  riskLevel: string;
  confidence: number;
}>) {
  // Reset counters
  activePredictions.reset();

  // Count by type and risk level
  const counts: Record<string, Record<string, number>> = {};

  for (const prediction of predictions) {
    if (!counts[prediction.type]) {
      counts[prediction.type] = {};
    }
    if (!counts[prediction.type][prediction.riskLevel]) {
      counts[prediction.type][prediction.riskLevel] = 0;
    }
    counts[prediction.type][prediction.riskLevel]++;

    predictionConfidence.observe(prediction.confidence);
  }

  // Update gauges
  for (const [type, riskLevels] of Object.entries(counts)) {
    for (const [riskLevel, count] of Object.entries(riskLevels)) {
      activePredictions.set({ type, risk_level: riskLevel }, count);
    }
  }
}

// Initialize metrics registry
export function initializeMetrics() {
  // Register all metrics with Prometheus
  register.registerMetric(systemHealthStatus);
  register.registerMetric(cpuUsage);
  register.registerMetric(memoryUsage);
  register.registerMetric(diskUsage);
  register.registerMetric(connectionPoolUsage);
  register.registerMetric(activePredictions);
  register.registerMetric(predictionConfidence);
  register.registerMetric(riskLevelCounts);
  register.registerMetric(anomalyCount);
  register.registerMetric(anomalyDetectionTime);
  register.registerMetric(capacityForecastDays);
  register.registerMetric(capacityForecastAccuracy);
  register.registerMetric(maintenanceTicketsCreated);
  register.registerMetric(maintenanceTicketsResolved);
  register.registerMetric(notificationsSent);
  register.registerMetric(notificationLatency);
  register.registerMetric(mlModelAccuracy);
  register.registerMetric(mlModelTrainingTime);
  register.registerMetric(mlModelPredictionTime);
  register.registerMetric(serviceUptime);
  register.registerMetric(metricCollectionDuration);
  register.registerMetric(predictionGenerationDuration);
  register.registerMetric(predictionErrors);
  register.registerMetric(metricCollectionErrors);
}