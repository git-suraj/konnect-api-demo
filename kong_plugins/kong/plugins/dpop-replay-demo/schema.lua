local schema = {
  name = "dpop-replay-demo",
  fields = {
    {
      config = {
        type = "record",
        fields = {
          {
            replay_ttl_seconds = {
              type = "integer",
              required = true,
              default = 300,
              between = { 1, 3600 },
            },
          },
          {
            cache_prefix = {
              type = "string",
              required = true,
              default = "dpop-replay-demo",
            },
          },
        },
      },
    },
  },
}

return schema
