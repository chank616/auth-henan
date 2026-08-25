# 豫高联认证

面向河南高校联合皮肤站的学校统一身份认证插件，适用于 Blessing Skin 5/6。

本项目采用“每所学校由本校同学维护”的方式持续扩展：各校社长在校内分配熟悉统一认证流程的同学负责对应 Provider，豫高联皮肤站负责人负责跨学校沟通和主仓库维护。

## 已支持学校

| 学校 | 标识 | 状态 |
| --- | --- | --- |
| 华北水利水电大学 | `ncwu` | 已接入 |
| 郑州大学 | `zzu` | 已接入 |

## 工作方式

1. 用户可在注册页面选择使用高校账号注册，并提交学校、统一认证账号、统一认证密码、皮肤站密码、角色名和验证码。
2. 注册验证成功后，插件使用“学号 + 学校邮箱后缀”创建皮肤站账号，将邮箱标记为已验证，并保存用户自设皮肤站密码的不可逆哈希。
3. 已注册用户可在独立的高校认证登录页面提交学校、统一认证账号和密码完成登录，无需再次填写角色名。
4. 统一认证密码只用于学校身份验证，不会保存或覆盖皮肤站密码；普通网页登录和 PCL 等启动器均使用皮肤站邮箱或角色名及用户自设的皮肤站密码。

所有学校认证均使用 PHP 实现，不需要 Python、Node.js 或额外的常驻服务。

## 贡献流程

1. 各校社长确定本校负责同学。
2. 负责人 Fork 本仓库，并在自己的 Fork 中创建分支。
3. 在该分支修改本校 Provider；新增学校时，同时更新 `src/SchoolRegistry.php`。
4. 将改动推送到自己的 Fork，然后向本仓库的 `main` 分支提交 Pull Request。

无需认领 Issue，也无需添加主仓库协作者。具体代码要求见 [CONTRIBUTING.md](CONTRIBUTING.md)。

推荐使用 AI 辅助开发。开始前请让 AI 阅读 [AGENTS.md](AGENTS.md) 或 [CLAUDE.md](CLAUDE.md)，并参考 [Blessing Skin 官方插件开发文档](https://bs-plugin.netlify.app/)。AI 生成的代码由提交者自行检查后再提交。

## 项目结构

```text
src/
├── SchoolRegistry.php            # 学校注册表与 Provider 调度
├── Schools/                      # 各学校 Provider
│   ├── NcwuAuth.php              # 华水 Provider
│   └── ZzuAuth.php               # 郑大 Provider
└── Utils/                        # Provider 共用接口与工具
    ├── SchoolAuth.php            # 学校认证统一接口
    ├── MfaCapableSchoolAuth.php  # 多因素认证 Provider 接口
    ├── MfaRequiredException.php  # 多因素认证挑战信息
    ├── JSEncrypt.php
    ├── KingoDes.php
    └── RSAUtils.php
```

## 贡献者

<a href="https://github.com/chank616/auth-henan/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=chank616/auth-henan&columns=12" alt="项目贡献者">
</a>

🌸 头像墙会根据 GitHub 贡献记录自动更新。[@Homoarea](https://github.com/Homoarea) 为原始作者。

## License

[MIT License](LICENSE)
