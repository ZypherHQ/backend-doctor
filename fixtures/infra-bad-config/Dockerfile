FROM node:latest
ENV NODE_ENV=production
ARG API_TOKEN=bd_fixture_token_123456
RUN apt-get update && apt-get install -y build-essential gcc make
WORKDIR /app
COPY . .
EXPOSE 5432
CMD ["npm", "run", "dev"]
