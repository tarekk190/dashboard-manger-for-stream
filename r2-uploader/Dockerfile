FROM node:20-alpine

WORKDIR /usr/src/app

COPY package.json ./
RUN npm install --omit=dev

COPY uploader.js ./

ENV NODE_ENV=production
ENV HLS_DIR=/hls

CMD ["node", "uploader.js"]
