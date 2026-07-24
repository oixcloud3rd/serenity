---
icon: material/file-code
---

# 从源代码构建

## :material-graph: 要求

* Go 1.26 或更高版本

您可以从 https://go.dev/doc/install 下载并安装 Go，推荐使用最新版本。

## :material-fast-forward: 构建

```bash
make
```

如需启用 `oixcloud://` 托管订阅，请在链接时通过构建变量注入订阅签名密钥：

```bash
OIXCLOUD_SUBSCRIPTION_HMAC_KEY='your-key' make build
```

本地构建可不提供密钥；此时 HTTP、文件等其他订阅来源不受影响，仅在使用 `oixcloud://` 时返回明确错误。官方 Docker 镜像与发布软件包必须配置同名仓库 Secret。Docker 通过 BuildKit secret 传入密钥，不会将其写入构建参数或镜像层：

```bash
docker build \
  --secret id=oixcloud_hmac_key,env=OIXCLOUD_SUBSCRIPTION_HMAC_KEY \
  -t serenity .
```

或者构建二进制文件并将其安装到 `$GOBIN`：

```bash
make install
```
