# Contributing

## Add a feed via Pull Request

1) Edit one of the files in `feeds/*.yaml` (choose the closest category)
2) Add a new item:

```yaml
- url: https://example.com/feed.xml
  title: Example Security Blog
  description: Short description (optional)
  type: rss   # rss|atom (optional)
  category: Research
```

## Rules

- `url` is required and should be a direct RSS/Atom feed URL
- Avoid duplicates (same URL)
- Keep titles/descriptions short

CI will validate duplicates automatically.
