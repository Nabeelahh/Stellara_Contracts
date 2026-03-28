# Predictive Maintenance System

The Predictive Maintenance System provides ML-based forecasting and anomaly detection for infrastructure failures, capacity issues, and performance degradation in the Stellara platform.

## Features

- **Real-time Metric Collection**: Monitors CPU, memory, disk usage, and connection pools
- **Statistical Anomaly Detection**: Uses 3-sigma rule for detecting abnormal system behavior
- **Capacity Forecasting**: Predicts disk full scenarios and connection pool exhaustion
- **Failure Prediction**: Identifies potential infrastructure failures before they occur
- **Automated Maintenance Tickets**: Creates tickets with confidence scores and risk levels
- **Notification Integration**: Sends alerts to Slack and PagerDuty
- **ML Model Management**: Tracks model versions and performance metrics

## API Endpoints

### Health & Metrics
- `GET /predictive-maintenance/health` - Get system health status
- `GET /predictive-maintenance/metrics` - Get current system metrics
- `GET /predictive-maintenance/forecast?days=7` - Get capacity forecasts

### Predictions & Analysis
- `GET /predictive-maintenance/predictions?type=cpu` - Get active predictions
- `GET /predictive-maintenance/anomalies?hours=24` - Get detected anomalies
- `POST /predictive-maintenance/analyze` - Trigger manual analysis

### Maintenance
- `GET /predictive-maintenance/maintenance-tickets?status=open` - Get maintenance tickets
- `GET /predictive-maintenance/model-performance` - Get ML model performance

## Configuration

Add the following environment variables:

```env
# Slack Integration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# PagerDuty Integration
PAGERDUTY_ROUTING_KEY=your-routing-key
PAGERDUTY_INTEGRATION_KEY=your-integration-key

# Prediction Thresholds
PREDICTION_CONFIDENCE_THRESHOLD=0.8
ANOMALY_DETECTION_SIGMA=3
```

## Scheduled Tasks

The system runs automated tasks:

- **Every 5 minutes**: Collect system metrics
- **Every hour**: Run predictions and anomaly detection
- **On startup**: Perform initial full analysis

## Risk Levels

- **Low**: Confidence < 0.6, minor issues
- **Medium**: Confidence 0.6-0.8, potential issues
- **High**: Confidence 0.8-0.9, significant risk
- **Critical**: Confidence > 0.9, immediate action required

## Database Models

### SystemMetric
Stores time-series infrastructure metrics:
- CPU usage and load averages
- Memory usage
- Disk usage
- Connection pool statistics

### MetricPrediction
Stores ML predictions with confidence scores:
- Prediction type (cpu, memory, disk, connections)
- Risk level and confidence score
- Predicted failure time
- Recommendation actions

### MaintenanceTicket
Automated maintenance tickets:
- Title and description
- Priority and status
- Associated predictions
- Resolution notes

### MaintenanceNotification
Notification history:
- Channel (slack, pagerduty)
- Status and response
- Error details

### MLModel
Model performance tracking:
- Model version and type
- Accuracy metrics
- Training data statistics

## Usage Examples

### Check System Health
```bash
curl http://localhost:3000/predictive-maintenance/health
```

### Get Current Metrics
```bash
curl http://localhost:3000/predictive-maintenance/metrics
```

### View Active Predictions
```bash
curl http://localhost:3000/predictive-maintenance/predictions
```

### Trigger Manual Analysis
```bash
curl -X POST http://localhost:3000/predictive-maintenance/analyze
```

## Monitoring & Alerts

The system integrates with existing monitoring infrastructure:

- **Prometheus Metrics**: Exposed via `/metrics` endpoint
- **Grafana Dashboards**: Pre-built dashboards for predictions
- **Alert Manager**: Configurable alert rules based on risk levels

## Development

### Running Tests
```bash
npm run test predictive-maintenance
```

### Adding New Metrics
1. Update `SystemMetrics` interface
2. Add collection logic in `gatherSystemMetrics()`
3. Update anomaly detection algorithms
4. Add forecasting logic if applicable

### Custom ML Models
1. Implement new algorithm in service methods
2. Update `MLModel` tracking
3. Add performance validation
4. Update confidence scoring

## Troubleshooting

### Common Issues

1. **High false positive rate**: Adjust sigma threshold or confidence levels
2. **Missing metrics**: Check system permissions for metric collection
3. **Notification failures**: Verify webhook URLs and API keys
4. **Database performance**: Add indexes for time-series queries

### Logs
Check application logs for detailed error information:
```bash
grep "PredictiveMaintenance" logs/application.log
```

## Future Enhancements

- Advanced ML models (LSTM, Prophet)
- Multi-cloud metric aggregation
- Predictive scaling recommendations
- Integration with incident management systems
- A/B testing for prediction accuracy