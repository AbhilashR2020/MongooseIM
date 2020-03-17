-record(file_upload, {
  path = "",
  token = "",
  expires = 0,
  jid,
  download_count,
  created_at,
  request_id,
  thumbnails = []
}).