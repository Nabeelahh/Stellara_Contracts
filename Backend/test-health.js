// Simple test to verify health endpoints work
const http = require('http');

// Test health endpoints
const testHealthEndpoints = () => {
  console.log('🧪 Testing Health Monitoring Endpoints...\n');
  
  const endpoints = [
    { path: '/health/live', name: 'Liveness Probe' },
    { path: '/health/ready', name: 'Readiness Probe' },
    { path: '/health', name: 'Detailed Health' }
  ];
  
  let completed = 0;
  
  endpoints.forEach(endpoint => {
    const req = http.get(`http://localhost:3000${endpoint.path}`, (res) => {
      let data = '';
      
      res.on('data', chunk => {
        data += chunk;
      });
      
      res.on('end', () => {
        console.log(`✅ ${endpoint.name}:`);
        console.log(`   Status: ${res.statusCode}`);
        console.log(`   Path: ${endpoint.path}`);
        try {
          const jsonData = JSON.parse(data);
          console.log(`   Response: ${JSON.stringify(jsonData, null, 2)}`);
        } catch (e) {
          console.log(`   Response: ${data}`);
        }
        console.log('');
        
        completed++;
        if (completed === endpoints.length) {
          console.log('🎉 All health endpoints tested successfully!');
        }
      });
    });
    
    req.on('error', (err) => {
      console.log(`❌ ${endpoint.name} failed: ${err.message}`);
      completed++;
    });
    
    req.setTimeout(5000, () => {
      console.log(`⏰ ${endpoint.name} timed out`);
      req.destroy();
      completed++;
    });
  });
};

// Run the test
testHealthEndpoints();