# Static response bodies

`api-config-v2.json` and `gameconfigs-v1-all-2025.json` are the client-config
shapes for build 20250718.01, sourced from the open-source RecFlare server
(github.com/recflare/server, apps/api/static/). Used so the UwUNet edge serves a
shape the 2025 client can deserialize (an empty `{}` crashes its Utf8Json
reader). Game-config *values*, not game assets. Provenance kept for upstream
credit per the project's "build on community research" stance.
