# 保持 Community 官方运行契约

首版 OCI 镜像默认保持 ONLYOFFICE Community 单镜像启动行为，并继续支持通过既有环境变量连接外部 PostgreSQL、Redis 和 RabbitMQ，不强制引入新的多容器服务拓扑。源码构建的 JetOnlyOffice 镜像应能够按同版本官方镜像的部署契约替换使用，部署架构重构不与 Mobile 编辑首版绑定。
