import request from "@/utils/request";

export function getDocuments(params) {
  return request({
    url: "/dms/papers/",
    method: "get",
    params
  });
}
