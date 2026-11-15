# Harukawa Sayaka's Blog

- Website: [baka.studio](https://baka.studio)
- Theme: [hugo-theme-stack](https://github.com/CaiJimmy/hugo-theme-stack)
- Powered by: [Hugo](https://gohugo.io/)
- Deployed to: [Vercel](https://vercel.com/)

## 本地开发

- Hugo ≥ 0.170（extended 或标准版均可），版本与 `vercel.json` 中的 `HUGO_VERSION` 保持一致
- [Dart Sass](https://sass-lang.com/dart-sass/)：主题样式需要它编译（`scoop install sass`）；Vercel 构建时会在 `installCommand` 中自动下载
- 更新主题：`git -C themes/hugo-theme-stack fetch --tags && git -C themes/hugo-theme-stack checkout <tag>`

```sh
git submodule update --init
hugo server
```

## 嵌入独立 HTML 页面

把页面拆成 `assets/embeds/<name>/{body.html,style.css,script.js}`（样式需限定在 `.article-content .sl` 下），然后在文章里写 `{{</* embed-page "<name>" */>}}`。
