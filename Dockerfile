FROM mcr.microsoft.com/playwright:v1.56.1-jammy
WORKDIR /app
COPY package.json ./
RUN npm i -g pnpm && pnpm i --prod=false
COPY tsconfig.json ./
COPY src ./src
RUN pnpm build
EXPOSE 3000
CMD ["node", "--enable-source-maps", "dist/server.js"]
