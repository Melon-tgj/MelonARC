# Privacy statement / 隐私声明

MelonARC is a local proxy client. This statement describes the macOS preview
shell and the shared Go core it embeds.

MelonARC 是本地代理客户端。本文档说明 macOS 预览版原生壳及其内置的共享 Go 核心。

## What leaves the machine / 什么会离开本机

- The application does not send analytics, telemetry, crash reports, contact
  lists, or diagnostic text to the project.
- 本程序不向项目方发送分析数据、遥测、崩溃报告、通讯录或诊断文本。
- Network traffic follows the rules and outbound proxies you configure. A
  subscription URL is contacted only when that subscription is imported or
  refreshed.
- 网络流量按用户配置的规则与出站代理转发；只有在导入或刷新订阅时才会访问该订阅地址。
- Proxy servers and rule providers you configure receive the connections you
  ask this application to carry. Their own privacy practices are theirs.
- 用户配置的代理服务器与规则提供方会收到本程序按配置转发的连接，其隐私行为由其自身负责。

## What stays on the machine / 什么留在本机

The data directory holds the loopback API token (`api-token`, mode 0600), the
core configuration, `core.log`, the observation history database, cached
subscription bodies, and the system-proxy snapshot. The shell settings file
holds only paths, the API address, and a record of the first resolved data
directory. The file lock is released on exit.

数据目录保存回环 API 令牌（`api-token`，权限 0600）、核心配置、`core.log`、
观测历史数据库、订阅缓存与系统代理快照。壳设置文件只保存路径、API 地址与
首次解析到的数据目录记录。文件锁在退出时释放。

The local control API binds only to a loopback address and requires a bearer
token read from that data directory. The shell's control session bypasses the
system proxy and refuses redirects.

本地控制 API 只绑定回环地址，并要求使用该数据目录中的 Bearer 令牌。壳的控制会话
绕过系统代理并拒绝任何重定向。

## System proxy / 系统代理

If you enable the system proxy, the core writes the previous values to a local
snapshot before changing the desktop proxy settings, and restores them on a
clean exit. If a restore fails, the snapshot is kept for the next start and the
interface shows the recovery-failed state. Quitting the application from its
menu or ⌘Q is the supported way to trigger that restore.

启用系统代理后，核心会先把原值写入本地快照，再修改桌面代理设置，并在正常退出时
恢复。恢复失败时快照会留待下次启动，界面会显示“快照恢复失败”。从菜单或 ⌘Q 退出
是触发恢复的受支持方式。

## Removing local data / 清除本机数据

Quit the application so the proxy snapshot can be restored, then remove the
data directory shown in Settings. Deleting it while the application is running
can leave a system-proxy snapshot with no recovery path.

先退出应用以便恢复系统代理，再删除“设置”中显示的数据目录。运行时删除会让系统代理
快照失去恢复入口。

## Scope / 范围

This statement covers this preview build only. A released build may update it;
the bundled copy in each candidate image is the one that applies to that build.

本声明只覆盖此预览版本。正式版本可能更新；每个候选包内附带的副本适用于该构建。
