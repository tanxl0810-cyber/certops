# 第三方组件说明

Apache-2.0 许可证覆盖本项目原创代码，不改变依赖及基础镜像原有的许可证。本源码仓库通过包管理器引用依赖，不将这些项目改名为 CertOps 自有代码。

以下为当前直接依赖及声明的许可证概览。许可证原文、包内归属说明与实际分发的具体版本优先于此表。

| 组件 | 版本 | 许可证 |
| --- | --- | --- |
| FastAPI | 0.143.1 | MIT |
| Uvicorn | 0.54.0 | BSD-3-Clause |
| SQLAlchemy | 2.1.4 | MIT |
| psycopg / psycopg-binary | 3.3.6 | LGPL-3.0-only |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| HTTPX | 0.28.1 | BSD-3-Clause |
| argon2-cffi | 25.1.0 | MIT |
| aliyun-python-sdk-core | 2.16.1 | Apache-2.0 |
| Paramiko | 5.1.0 | LGPL-2.1 |
| oss2 | 2.19.1 | MIT |
| alibabacloud-fc20230330 | 4.8.4 | Apache-2.0 |
| alibabacloud-tea-openapi | 0.4.6 | Apache-2.0 |
| darabonba-core | 1.0.10 | Apache-2.0 |
| Vue | 3.5.44 | MIT |
| Vite | 8.3.5 | MIT |
| @vitejs/plugin-vue | 6.0.10 | MIT |

完整依赖来源和版本见 [requirements.txt](requirements.txt) 与 [ui/package-lock.json](ui/package-lock.json)。Python 传递依赖由 pip 解析，不能将此直接依赖表视为完整软件物料清单。

## 分发保留

- 前端构建会读取已安装 npm 包的 LICENSE、COPYING 和 NOTICE，生成 `app/static/third-party-notices.txt`，随浏览器静态文件分发。
- Docker 构建保留 Python 包原有许可证文件，并在 `/usr/share/doc/certops/PYTHON_NOTICES.txt` 汇总实际安装包的许可及归属信息。
- Python、Node.js、PostgreSQL、Debian 基础镜像及其系统软件包遵循各自许可证，相关原始说明随对应镜像保留。
- 不要在二次打包时删除上述原始许可文件。修改或重新分发 LGPL 组件时，还需遵守对应版本对源码、修改说明及重新组合等事项的要求；本项目的 Apache-2.0 不替代这些要求。

组件源代码及发行文件可从其对应的 PyPI / npm 包页面、包元数据列出的上游仓库和官方基础镜像来源获取。发布二次构建的镜像或离线包时，应根据实际包含的版本重新生成并核对通知与源码提供义务。
