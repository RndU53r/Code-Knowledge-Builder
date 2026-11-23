# Entry-point patterns by language

Use these to find candidates the regex inventory missed. Confirm each one by reading the code.

| Kind | Python | Node/TS | Go | Java/Kotlin | Rust | Other |
| --- | --- | --- | --- | --- | --- | --- |
| Process main | `if __name__ == "__main__"`, `[project.scripts]` in pyproject, `console_scripts` | `package.json` `main`/`bin`, `node x.js` in Dockerfile CMD | `package main` + `func main()` under `cmd/*` | `public static void main`, Spring `@SpringBootApplication` | `fn main()` in `src/main.rs`, `[[bin]]` | Dockerfile `CMD`/`ENTRYPOINT`, `Procfile` |
| HTTP | FastAPI/Flask decorators, Django `urls.py`, `APIRouter` include prefixes | Express/Koa/Fastify routes, Nest `@Controller` + method decorators, Next.js `pages/api`, `app/**/route.ts` | `http.HandleFunc`, gin/echo/chi/fiber routers, route groups (combine prefixes) | `@RequestMapping` family, JAX-RS `@Path` | axum/actix routers, `#[get]` | nginx/envoy/ingress routes map external paths to services |
| gRPC | `add_*Servicer_to_server` | `server.addService` | `Register*Server` | `@GrpcService`, `BindableService` | tonic `*Server::new` | `.proto` `service` blocks are the contract |
| GraphQL | graphene/strawberry schema | Apollo `typeDefs` + resolvers | gqlgen `schema.graphqls` | graphql-java | async-graphql | schema files |
| Queue consumer | `basic_consume`, `KafkaConsumer`, Celery `@task`, SQS `receive_message` loops | kafkajs `consumer.run`, amqplib `consume`, SQS pollers, Bull/BullMQ `Worker` | `amqp.Consume`, kafka-go `NewReader`, sarama consumer groups | `@KafkaListener`, `@RabbitListener`, `@SqsListener` | rdkafka `StreamConsumer`, lapin | AsyncAPI documents |
| Scheduled | Celery beat, APScheduler, `schedule` | node-cron, Agenda | robfig/cron | `@Scheduled`, Quartz | tokio-cron | K8s `CronJob`, GitHub Actions `schedule:`, crontab files |
| Serverless | `handler(event, context)` | `exports.handler` | `lambda.Start` | `RequestHandler` | `lambda_runtime` | `serverless.yml`, SAM `template.yaml`, Terraform `aws_lambda_function.handler` |
| Webhook | routes named `/webhook*` or a signature check (`X-Hub-Signature`, Stripe-Signature) | same | same | same | same | gateway config |
| CLI | argparse, click, typer | commander, yargs, oclif | cobra, urfave/cli, `flag` | picocli | clap | `Makefile` targets are build-time, not runtime |

Route prefixes: combine router mounts (`app.use('/api', router)`, `include_router(prefix=...)`, `r.Group("/v1")`) to get the full external path, and cite both the mount and the route.
