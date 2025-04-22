## DRAKVUF Sandbox frontend development notes

If you want to run this React app with external DRAKVUF Sandbox API server:

```shell
$ VITE_API_SERVER="http://<your-api-server>" npm run dev
```

Flask app must be run with `DRAKRUN_CORS_ALL=1` environment variable to share resources with external origins
(e.g. your localhost web app). This setting is recommended only for a development environment. 
