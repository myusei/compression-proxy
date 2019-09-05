from PIL import Image
import io, time, gzip
import brotli
path = '/var/log/mitmproxy/mitm_filter.log'

def response(flow):
    if "content-type" in flow.response.headers and "content-length" in flow.response.headers:
        ct = str(flow.response.headers["content-type"])
        cl = int(flow.response.headers["content-length"])
        s = io.BytesIO(flow.response.content)
        s2 = io.BytesIO()
        if (cl) > 100:

            # 画像をjpeg quality 10/100に変換する
            if (ct) [0:6] == ("image/") and (cl) > 1000 and (ct) [0:9] != ("image/svg"):
                start = time.time()
                if (ct) [0:9] == ("image/png"):
                    img = Image.open(s)
                    if img.mode == "RGBA" or "transparency" in img.info:
                        img.save(s2, "png", optimize = True, bits = 8)
                    else:
                        img = Image.open(s).convert("RGB")
                        #img = Image.open(s).convert("L")
                        img.save(s2, "jpeg", quality = 10, optimize = True, progressive = True)
                        flow.response.headers["content-type"] = "image/jpeg"
                else:
                    img = Image.open(s).convert("RGB")
                    img.save(s2, "jpeg", quality = 10, optimize =  True, progressive = True)
                    flow.response.headers["content-type"] = "image/jpeg"
                flow.response.content = s2.getvalue()
                return

            # スキームが http のテキストを gzip 圧縮する
            if flow.request.scheme == "http" and not "content-encoding" in flow.response.headers:
                flow.response.headers["content-encoding"] = "none"     
                if (ct) [0:5] == ("text/") or (ct) [0:12] == ("application/") or (ct) [0:9] == ("image/svg"):
                    gz = gzip.GzipFile(fileobj=s2, mode='w')
                    gz.write(flow.response.content)
                    gz.close()
                    flow.response.content = s2.getvalue()
                    flow.response.headers["content-encoding"] = "gzip"
            # スキームが https のテキストを brotli 圧縮する
            elif flow.request.scheme == "https" and not "content-encoding" in flow.response.headers:
                flow.response.headers["content-encoding"] = "none"
                if (ct) [0:5] == ("text/") and (ct) [0:10] != ("text/plain") and (ct) [0:9] != ("text/html") or (ct) [0:12] == ("application/") and (ct) [0:16] != ("application/json") or (ct) [0:9] == ("image/svg"):
                    s2 = flow.response.content
                    s3 = brotli.compress(s2, quality=10)
                    flow.response.content = s3
                    flow.response.headers["content-encoding"] = "br"
                
                
