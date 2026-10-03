# Safe Wallet

多签钱包策略引擎：阈值策略、签名收集、重放防护与执行队列，以及由当前阈值签名决定的策略变更任务。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现（纯标准库：secp256k1 ECDSA、RFC 6979、sha3-256 载荷摘要）。

## 结构

- `safewallet/crypto.py` — secp256k1 签名/验证/地址恢复，规范字段编码与域分离载荷摘要。
- `safewallet/engine.py` — `Wallet`、`Policy`、`Task` 与执行队列。
- `safewallet/errors.py` — 公开异常体系。
- `tests/` — 行为测试。

## 公开行为

### 普通交易（既有行为）

`submit_transfer(to, amount, nonce, deadline, signatures)`：

1. 校验截止时间（过期 → `RequestExpired`）、字段（非法 → `InvalidTransaction`）、nonce（已使用 → `NonceAlreadyUsed`；顺序错误 → `InvalidTransaction`）、阈值签名（不足或非所有者签名 → `InvalidTransaction`，重复签名只计一次）。
2. 校验通过后生成待执行任务进入队列，nonce 随之消费。
3. 相同请求的重复提交幂等返回同一任务（不重复入队、不重复消费 nonce）。
4. `execute(task_id)` / `execute_next()` 按提交顺序执行；`executed`/`failed` 为终态，终态任务再次执行幂等返回。

普通交易的签名载荷不携带策略版本字段。

### 策略变更任务（本次新增）

`submit_policy_change(new_owners, new_threshold, version, nonce, deadline, signatures)`：

- 签名载荷明确绑定钱包标识、`POLICY_CHANGE` 操作、当前策略版本、新所有者列表、新确认数、nonce 与截止时间。
- 新所有者列表不能为空、不能重复、不能含零地址；新确认数须大于零且不超过新所有者数量。
- 任何策略字段不合法、阈值签名不足、签名载荷不匹配、版本不匹配或 nonce 顺序不正确，都只抛出 `InvalidPolicyChange`：不创建任务、不消费 nonce、不改变当前策略。
- 已使用的 nonce 沿用既有重放防护抛出 `NonceAlreadyUsed`；截止时间早于当前时间抛出 `RequestExpired`。
- 校验通过的任务进入同一执行队列，沿用既有排序、防重与终态规则。

执行时仅当当前版本仍等于提交时绑定的版本才生效：所有者集合与确认数同时替换为提交值，策略版本递增一次，任务进入 `executed` 终态；此后使用旧版本、旧 nonce 或旧签名的请求无法再次生效。若执行前版本已变化，任务进入 `failed` 终态并抛出 `PolicyConflict`，策略内容不变。

## 测试

```bash
python3 -m pytest tests/
```

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
