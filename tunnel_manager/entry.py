# -*- coding: utf-8 -*-
"""tunnel_manager.entry — 进程入口 main()

由 P1 从 server.py 的第 6860–6883 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：main
本模块依赖其它切片：_base、config、web/httpd
"""
>>>SLICE_BODY<<<
def main():
    port = pick_port()
    start_auto_tracker()   # 拉起浏览器历史自动追踪线程
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        print(f"无法绑定端口：{e}", file=sys.stderr)
        sys.exit(1)
    url = f"http://127.0.0.1:{port}"
    print(f"Universal Tunnel Manager 已启动（{PLATFORM}）：{url}")
    print("只绑 127.0.0.1，仅本机可访问。Ctrl-C 退出。")
    threading.Thread(target=lambda: (time.sleep(1.2), webbrowser.open(url)),
                     daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n再见。")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

