FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

# Install all production dependencies (including git dependencies like nodemailer)
RUN apk add --no-cache git && npm ci --only=production

COPY . .

ENV PORT=8080
EXPOSE 8080

CMD ["node", "./bin/www"]
