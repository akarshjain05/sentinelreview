FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY . .

EXPOSE 5173

# --host 0.0.0.0 is required for the dev server to be reachable from
# outside the container (Vite binds to localhost only by default, which
# would be unreachable from the host machine's browser).
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
