# Migrations

本目录保存 PostgreSQL 迁移。`0001_initial_schema.sql` 是 V1 Core 的冻结初始结构，只允许通过 `run-0001.sh` 对已确认的空库执行。

## Schema Freeze 结论

- 用户已于 2026-07-21 确认旧 `0001` 从未进入共享开发库、测试库或生产库，本次采用“重写 `0001`”路径，不新增兼容 P1 骨架的 `0002`。
- 用户已于 2026-07-22 接受账号登录与设备身份 ADR，并再次确认 `0001` 未进入共享环境；本轮继续重写 final `0001`，不连接或迁移任何现有 PostgreSQL。
- `0001_initial_schema.sql` 已标记为 `SCHEMA_FREEZE_STATUS=FINAL`，包含 43 张 V1 表、完整 CHECK/FK/index 和 7 个跨表一致性 trigger。
- V1 实际建表包括账号与登录态、MFA/风险、反诈、设备与策略、组织/角色/设备组、会话与连接、远程重启、Relay、文件传输、客户端发布和审计模型。
- `organization_region_policies`、`region_catalog`、`object_storage_locations`、`session_recording_policies`、`session_recordings`、`session_recording_access_logs` 是 M8/V2 预留表，不在 V1 `0001` 中创建。
- V1 只保留 `relay_nodes.data_residency_class`、`relay_session_stats.region_policy_id/region_policy_version` 和 `client_release_artifacts.storage_location_id` 等 nullable 预留列，不对 M8 表建立强 FK。
- `connection_candidates` 只持久化候选事实和 `observe_result_id`，不包含 `candidate_token`、`candidate_token_binding_hash` 或 token `expires_at_epoch_millis`。
- 一旦 `0001` 被任何共享环境使用，后续只能新增递增迁移，不得继续修改 `0001`。共享或生产迁移仍需单独确认。

## 相对 P1 骨架的 Delta

凭据和账号安全：

- 删除临时验证码 `code_hash` 骨架口径，改为固定 `opaque_ristretto255_sha512_v1` 的 verifier、salt、server nonce、challenge 状态、5 分钟 challenge 上限、24 小时 code 上限、尝试次数和消费时间。
- 补 `account_sessions`、`api_idempotency_keys`、`account_mfa_factors`、`mfa_recovery_code_deliveries`、`account_recovery_codes`、`account_risk_challenges`、`device_enrollment_grants`、`trusted_controller_devices`，敏感凭据只存 hash、密文或 OPAQUE record。
- 补风险 challenge 的设备、purpose、`operation_binding_hash`、风险等级、状态、最多 5 次尝试、5 分钟有效期和一次性消费约束；`login_mfa` 额外保存设备状态/公钥、fingerprint/ID/version、双 nonce、登录请求 binding、IP/User-Agent hash、可选 trusted-device、协议版本和初始尝试上限，供 Redis payload 丢失后恢复。
- enrollment grant 只保存 secret hash，并绑定账号、登录 challenge、拟注册设备 ID、公钥 fingerprint、协议版本和签发 session；最长 5 分钟且只能消费一次。消费时原子保存稳定注册 binding、首次 `public_key_id` 和可选 trusted-device ID，未消费/已消费结果形态由 CHECK 约束，trust 结果由同账号同设备复合 FK 约束。
- TOTP 恢复码交付只保存客户端可解密 ciphertext、双方临时公钥和 12-byte nonce；同账号/session/factor/幂等键只能生成一份结果，未确认密文最长保留 24 小时。
- `account_sessions.revoked_reason` 固定为 `logout | password_changed | mfa_enabled | mfa_disabled | account_locked | device_unbound | refresh_replay`，并与撤销时间同时为空或同时非空。

设备、权限和组织边界：

- 补设备平台/架构、OS 版本、当前公钥 ID/version/撤销时间和组织归属；平台固定为 `windows | ubuntu | ios`，架构固定为 `x86_64 | aarch64`。
- 补设备、组织、设备组、角色的 9 项会话权限和独立 `allow_remote_reboot`；组织/设备组能力使用 `inherit | allow | deny`，`require_prompt` 使用 `inherit | require | no_prompt`。
- 设备组成员通过 `(device_group_id, organization_id)` 和 `(organization_id, device_id)` 复合 FK 强制同组织；组织成员不能引用其他组织的自定义角色。
- 补 `access_policies`、`access_policy_assignments`、`device_access_rules`、`device_local_security_settings`、`policy_evaluations`，冻结 conditions/effects 原子键和三类策略决策枚举。
- 补反诈举报、案件、处置动作和风险事件表，所有 status/type/category/action/decision/risk_level 都落 SQL CHECK。

会话、连接和 Relay：

- `sessions.status` 替换旧 `invited/connecting`，冻结 13 个状态并保留独立终态 `rejected`；补 9 项 `permissions` 校验、`permissions_digest`、digest 变更时间、强 `policy_evaluation_id`、`relay_token_epoch`、会话过期、候选对和 Relay 关联。
- `session_events.event_type` 冻结为 25 个 V1 事件；补 event ID、actor 归因、裁剪 metadata 和追加记录边界。
- 补 `connection_candidates`、`connection_candidate_pairs` 的 role/kind/source/path/status CHECK、同会话复合 FK、角色/路径一致性 trigger 和必要索引。
- 候选 role 必须映射到会话实际 controller/controlled 设备；会话只能选择本会话候选对，且 transport path/Relay 节点必须与候选对一致。
- 补 `connection_candidates.observe_result_id`；短期 candidate token、完整 binding hash 和过期字段明确不落 PostgreSQL。
- 补 Relay 节点状态、协议能力、容量约束和 `relay_session_stats`；Relay 角色属于会话 token/`relay_open`，不在 `relay_nodes` 建 role 列。

高风险能力、传输和发布：

- 补 `remote_reboot_requests` 的不可变 API hash 快照、`reason_hash`、step-up 新鲜度、强策略评估 FK、自动恢复一次同意/撤销/消费、resume token ID/secret hash/消费/失效字段和固定枚举。
- 远程重启 trigger 固定 session/账号/双方设备/策略评估/permissions digest/step-up 绑定，并拒绝更新 canonical API hash 快照字段。
- 补 resume token ID 唯一索引、策略评估索引、会话状态索引、历史复合索引和过期索引。
- 补文件传输方向、被控端确认归因、取消归因、端侧路径 hash、安全保存策略、100MB 上限、固定失败原因和会话角色一致性 trigger；文件内容不落库。
- 补 `client_release_channels`、`client_release_artifacts`、`client_update_checks`，冻结 channel/scope/status、平台/架构、manifest 权威字段、发布者归因和更新阶段事件。

审计和删除策略：

- 补 `audit_logs.actor_type/actor_role/actor_service/resource_type/resource_id/metadata`、actor snapshot 和固定动作集合；`session_events` 使用相同 actor 组合约束。
- 所有审计归因相关 FK 使用 `ON DELETE RESTRICT`；整个迁移不使用 `ON DELETE CASCADE` 或 `ON DELETE SET NULL`。
- M8/V2 录制表和录制动作不进入 V1 迁移；区域审计动作可保留，但区域策略表仍按 M8 边界后置。

## 防误跑和执行

runner 同时执行以下门禁：

1. 必须显式设置 `SCHEMA_FREEZE_CONFIRMED=1`。
2. 必须显式设置 `SCHEMA_TARGET_EMPTY_CONFIRMED=1`。
3. `0001` 首行必须是 final 标记，且不能存在 draft/skeleton 标记。
4. 目标 `public` schema 必须没有 table、partitioned table、view、materialized view 或 foreign table。
5. 任一 SQL 错误立即停止；`--dry-run` 把最终 `COMMIT` 替换为 `ROLLBACK`。

事务 dry-run：

```bash
SCHEMA_FREEZE_CONFIRMED=1 \
SCHEMA_TARGET_EMPTY_CONFIRMED=1 \
DATABASE_URL='postgresql://postgres:postgres@127.0.0.1:5432/remote_empty' \
infra/migrations/run-0001.sh --dry-run
```

确认目标为空后执行：

```bash
SCHEMA_FREEZE_CONFIRMED=1 \
SCHEMA_TARGET_EMPTY_CONFIRMED=1 \
DATABASE_URL='postgresql://postgres:postgres@127.0.0.1:5432/remote_empty' \
infra/migrations/run-0001.sh --apply
```

对 fresh apply 结果执行只读结构验收：

```bash
psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -f infra/migrations/verify-0001.sql
```

不要直接调用 `psql -f infra/migrations/0001_initial_schema.sql` 绕过门禁。`T004` 的 Docker Compose 或部署 runner 必须复用等价检查。

本地 Compose 使用 `ensure-local-compose-schema.sh`：它只允许连接 Compose 内部的 `postgres:5432`；空 `public` schema 调用上述冻结 runner，非空 schema 只执行 `verify-0001.sql` 验证已有结构。部分结构、未知结构或外部 PostgreSQL 都会拒绝，不会尝试覆盖或修复。

## 验证记录

2026-07-22 已在全新隔离数据库 `remote_gate_clean_20260722` 完成真实验证，未连接或迁移既有 `remote-control-local` 数据库：

- `run-0001.sh --apply` 在空 `public` schema 成功执行，随后 `verify-0001.sql` 全部通过。
- `make fmt-check`、`make lint`、`make test`、`make check` 全部通过。
- PostgreSQL/Redis ignored 集成测试 `8 passed; 0 failed`，覆盖并发设备注册、设备密钥轮换撤销、完整会话与 MFA 密文、跨实例事务、Redis challenge/登录锁/在线状态和 TOTP lease。
- 静态检查确认 `0001` 首行为 final 标记、末行为 `COMMIT;`，runner 仍要求双确认和空 `public` schema，并在 dry-run 时替换为 `ROLLBACK;`。
- 完整环境、命令类别、结果和回滚边界见 `docs/report/schema-freeze/20260722172626679_T002P账号身份Schema验证报告.md`。

## 回滚

- `--dry-run` 始终在同一事务回滚，不产生持久结构。
- 对尚未共享的 fresh 本地验证库，回滚方式是丢弃该一次性数据库或本地 volume；删除数据库/volume 属于破坏性操作，必须单独确认。
- 不对已有数据的数据库执行 `0001`，因此不提供会误删业务数据的 down migration。
- `0001` 进入共享环境后，修正必须通过新的递增迁移完成，并为共享测试/生产环境单独提供备份、反向迁移或明确 no-op 回滚说明。
