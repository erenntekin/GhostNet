FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
# --legacy-peer-deps: react-simple-maps declares a React 18 peer dependency,
# this project runs React 19 -- works fine in practice, npm's strict peer
# resolution just doesn't know that yet.
RUN npm install --legacy-peer-deps

COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev"]
