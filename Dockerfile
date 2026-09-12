FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

RUN npm ci --only=production

COPY . .

# Google Cloud Run injects PORT (default 8080) at runtime
ENV PORT=8080
EXPOSE 8080

CMD ["node", "./bin/www"]
