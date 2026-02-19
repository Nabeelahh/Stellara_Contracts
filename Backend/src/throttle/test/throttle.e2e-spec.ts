import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../../app.module';

describe('ThrottleController (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('should enforce rate limit and return headers', async () => {
    const res = await request(app.getHttpServer()).get('/auth/login');

    expect(res.headers['x-ratelimit-limit']).toBeDefined();
  });

  it('should return 429 after exceeding limit', async () => {
    for (let i = 0; i < 6; i++) {
      await request(app.getHttpServer()).post('/auth/login');
    }

    const res = await request(app.getHttpServer()).post('/auth/login');
    expect(res.status).toBe(429);
  });
});
