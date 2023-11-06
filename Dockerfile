FROM node:18-alpine

WORKDIR /src/app

COPY package.json yarn.lock .

RUN yarn install --frozen-lockfile && yarn cache clean

COPY index.js .

EXPOSE 5353/udp

CMD ["/src/app/index.js"]
