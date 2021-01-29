# 사실 안됨

FROM ubuntu:latest

ENV TZ=Asia/Seoul
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN sed -ie 's/archive.ubuntu.com/mirror.kakao.com/g' /etc/apt/sources.list

RUN apt update && apt -y upgrade && apt -y autoremove

RUN apt install -y  sudo \
                    vim \
                    curl \
                    wget \
                    git \
                    libpcap-dev -y

RUN wget https://golang.org/dl/go1.15.7.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.15.7.linux-amd64.tar.gz
RUN echo export PATH=$PATH:/usr/local/go/bin >> /root/.bashrc

WORKDIR /test
COPY ./main.go .

RUN go get  "github.com/google/gopacket" \
            "github.com/google/gopacket/layers" \
            "github.com/google/gopacket/pcap" \
            "github.com/inancgumus/screen"

ENTRYPOINT ["bash"]