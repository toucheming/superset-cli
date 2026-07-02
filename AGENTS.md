# AGENTS.md — superset-query-cli

## 这是什么

单文件 CLI 工具（`py/query_superset.py`），通过 PyInstaller 打包成独立二进制。查询 Superset SQL Lab API 访问 DLC 数仓。**无测试、无测试框架、无 setup.py/pyproject.toml**。

## 源码与入口

- **`py/query_superset.py`** — 全部代码（1084 行）。直接运行：`python py/query_superset.py <参数>`
- **`superset-query.spec`** — PyInstaller 打包配置
- **`dist/linux/superset-query`** — 预编译 Linux 二进制
- **`dist/mac/superset-query`** — 预编译 macOS 二进制
- **`dist/win/superset-query.exe`** — 预编译 Windows 二进制

## 构建

```bash
./py/build.sh          # Linux（打包 → dist/linux/ → skills/query-superset/）
./py/build-mac.sh      # macOS（打包 → dist/mac/ → agent skill 目录）
./py/build.ps1         # Windows（打包 → dist/win/）
```

构建依赖：`pip install pyinstaller requests cryptography keyring`

## 运行时依赖（均可选）

- `requests` — API 调用必装
- `cryptography` — 配置文件中的 Fernet 密码加密
- `keyring` — 系统密钥链（优于文件加密）

## 配置与凭据

- 配置目录：`~/.config/superset-cli/`
- 凭据解析顺序：CLI 参数 → 环境变量（`SUPERSET_USERNAME`、`SUPERSET_PASSWORD`）→ 系统密钥链 → 加密配置文件 → 交互式输入
- 默认 Superset 地址：`http://43.138.226.32:8787`（可通过 `SUPERSET_URL` 环境变量、`--set-superset-url` 或配置文件覆盖）
- 默认数据源 ID：`4`（DataLakeCatalog，Doris 后端）
- 登录失败 → `rm -rf ~/.config/superset-cli/` 后重试；会话过期 → `--force-login`

## 关键查询规则

所有对 `DataLakeCatalog.*` 表的查询**必须**在 WHERE 中包含 `dt`。无一例外——即使是 LIMIT 5 的探查也不例外。不确定日期时，先查 `MAX(dt)`。分区表不带 `dt` 会全表扫描。

## 实用约束

- 内部数据库从列表中排除：`bigdata`、`bigdata_test`、`ods`、`warehouse`、`warehouse_test`
- Superset 登录需要 CSRF token（解析 HTML 页面获取，非纯 API 方式）
- 常用 Superset SQL：`SHOW DATABASES`、`SHOW TABLES [IN db]`、`SHOW CREATE TABLE`、`information_schema.COLUMNS`

## 交付物

编译后的二进制 → `dist/<platform>/superset-query`，同步到 `./.cursor/skills/query-superset/superset-query` 和 `./.opencode/skills/query-superset/superset-query`。用户手册见 `数仓查数工具使用说明.md`。Agent skill 配置在 `.opencode/skills/query-superset/SKILL.md`。
