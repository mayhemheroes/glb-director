FROM debian:stretch as builder

RUN echo 'deb http://ftp.debian.org/debian stretch-backports main' >>/etc/apt/sources.list
RUN apt-get update && apt-get -y install curl git

# DPDK 
RUN curl -s https://packagecloud.io/install/repositories/github/unofficial-dpdk-stable/script.deb.sh | bash
RUN apt-get update && apt-get install -y build-essential dpdk dpdk-dev wget pkg-config libjansson-dev libsystemd-dev clang-6.0

# iptables / DKMS
RUN apt-get update && apt-get install -y iptables-dev dkms debhelper libxtables-dev

# golang
RUN wget --quiet https://golang.org/dl/go1.14.8.linux-amd64.tar.gz -O- | tar -C /usr/local -zxvf -
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH="${GOPATH}/bin:${GOROOT}/bin:${PATH}"

# fpm for packaging
RUN apt-get update && apt-get install -y ruby ruby-dev rubygems build-essential
# pin fpm 1.11.0 until https://github.com/jordansissel/fpm/pull/1752 is fixed
RUN gem install --no-ri --no-rdoc rake fpm:1.11.0

# patch DKMS for source package generation https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832558
ADD script/helpers/dkms.diff /root/dkms.diff
RUN patch -d /usr/sbin </root/dkms.diff

# XDP
# linux-libc-dev must be upgraded to get a bpf.h that matches what we use. the rest match what we do in Vagrant for testing.
RUN apt-get update && apt install -y apt-transport-https curl software-properties-common
RUN apt-get update && apt install -y -t stretch-backports linux-image-4.19.0-0.bpo.9-amd64-unsigned linux-headers-amd64 iproute2 libbpf-dev linux-libc-dev
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sudo ./llvm.sh 10
ENV KVER 4.19.0-0.bpo.9-amd64

COPY . /repo
WORKDIR /repo/src/glb-director
RUN make -j8
WORKDIR /repo/src/glb-director/cli
RUN make -j8
RUN clang++-10 /repo/mayhem/fuzz_glb_log_info.cpp  -fsanitize=fuzzer,address -I /repo/src/glb-director -ljansson -o /fuzz

FROM debian:stretch as package
RUN apt-get update 
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libjansson-dev
COPY --from=builder /repo/src/glb-director/cli/glb-director-cli /
COPY --from=builder /fuzz /fuzz_glb_log_info
