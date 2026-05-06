FROM rust

RUN apt-get update && apt-get install -y --no-install-recommends \
        vsmartcard-vpcd libpcsclite-dev pcscd opensc git libclang-dev libdbus-1-dev nettle-dev pcsc-tools \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install --features="vpicc" --git https://github.com/Nitrokey/opcard-rs --tag v1.7.0 --example vpicc opcard
RUN cargo install openpgp-card-tools rage
COPY Cargo.toml Cargo.lock README.md /app/
COPY src /app/src
WORKDIR /app/
RUN cargo install --path .
COPY scripts /app/scripts
RUN ./scripts/encrypt-decrypt.sh
