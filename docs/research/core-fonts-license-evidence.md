# core-fonts 六项许可证证据研究

## 范围与判定规则

本记录只研究 `core-fonts` 锁定提交
[`7030c6681fb5bbed560675cb42422f91df15d5c9`](https://github.com/ONLYOFFICE/core-fonts/tree/7030c6681fb5bbed560675cb42422f91df15d5c9)
中的六个 unresolved 组件。SHA-256 均针对锁定 TTF 实体字节；字体 metadata
来自同一实体的 SFNT `name` 表和 `OS/2.fsType`。外部候选只采用字体权利人、
官方发行归档，或 Debian/Ubuntu 的版本化源码和发行包。

`fsType` 只描述字体嵌入权限，不能替代复制、修改和再分发许可。本文的
“可 reviewed”表示证据足以进入逐组件锁审查；在外部证据被镜像为不可变输入并
绑定摘要前，当前 source lock 仍须保持 unresolved。

| 组件 | payload 绑定 | 许可证结论 | 可 reviewed |
|---|---|---|---|
| `ASC.ttf` | 仅锁定字节和权利人 metadata | 无再分发授权 | 否 |
| `fonts-beng-extra` | 与 Debian `1.0-5` 源码和 DEB 逐字节相同 | `GPL-2.0-or-later`，无字体例外 | 有条件可以 |
| `fonts-gujr-extra` | 与 Debian `1.0-5` 源码和 DEB 逐字节相同 | `GPL-2.0-or-later`，无字体例外 | 有条件可以 |
| `kacst` | 与 Debian `2.01+mry-12` 源码逐字节相同 | `GPL-2.0-only` | 有条件可以 |
| `kacst-one` | 与 Ubuntu `5.0+svn11846-9` DEB 逐字节相同 | `GPL-2.0-only` | 有条件可以 |
| `liberation` | 16/16 payload 与 Debian 同版产物仅有 `head` 构建字段差异 | GPL v2 加专用条款；Sans Narrow 有冲突记录 | 否，需法律/ADR 审核 |

## `ASC.ttf`

锁定 payload：

```text
ASC.ttf  35ff902a3b9c9254ce3c57d610dad9e57008b8a3351691c463bee775644c1e18
```

- Git blob：`c33b59e7065328b1931888877a7c06b22eacc3bc`，大小 6,868 字节。
- metadata：family `ASCW3`，`Version 1.0`，copyright
  `Copyright (c) Ascensio System SIA 2012-2014. All rights reserved`；没有
  `name` ID 13/14 许可证字段，`fsType=0x0000`。
- 权威来源：ONLYOFFICE 的 [`Add asc font` 提交](https://github.com/ONLYOFFICE/core-fonts/commit/d834fb1817d4264aa012528428ff3a5ba6f7f001)、
  [`Add symbols for rtl` 提交](https://github.com/ONLYOFFICE/core-fonts/commit/06bd1bc36fa53d6dae94ed0a023e5fee41dd99e7)
  和 [PR #26](https://github.com/ONLYOFFICE/core-fonts/pull/26)。这些记录都未提供
  字体许可证；官方仓库也没有根许可证。
- 判定：**不可 reviewed**。公开 Git 提交、DocumentServer 的 AGPL 和
  `fsType=0` 都不是该字体的再分发授权。仍缺 Ascensio 对这一精确 payload 或
  `ASCW3` 字体系列的复制、修改和再分发许可，应保持 `MISSING_EVIDENCE`。

## `fonts-beng-extra`

锁定 payload：

```text
ani.ttf                 6159b004e0261b7f611eda29267ee6a462e9756d4b07b18addacb223b8eec650
JamrulNormal.ttf        61ed7222615ec8c9de9e8ca76212f5a63407c6255917de845671e479f7377b40
LikhanNormal.ttf        5a578e386f421b7076883d8a0b8a97cabaf07a0fbaa9b7ad2fd5b092959dabac
mitra.ttf               1ecf18397ac5b2979cdf8834ee09cc0060f9dfc41d8d09d0a581136a4a280747
MuktiNarrow.ttf         3a1201b75b290530d12239561f916d3a826e58f1232a5a49604a53dafc9bc716
MuktiNarrowBold.ttf     d71725f2e1f4b110f910dba7e66edd4f18d1e9d98f0a4d52f8b4c73368449116
```

- metadata：Ani `0.70`、Jamrul `0.1`、Likhan `0.6`、Mitra `0.70/0.50`、
  Mukti Narrow `0.94`；全部 `fsType=0x0000`。Jamrul、Likhan 明确写 GPL v2
  或更高版本，其余字体写 GNU/GPL 许可但未都给出版本。
- byte-identical：六个文件逐字节匹配
  [Debian Sources `fonts-beng-extra/1.0-5`](https://sources.debian.org/src/fonts-beng-extra/1.0-5/)
  和归档 DEB [`fonts-beng-extra_1.0-5_all.deb`](https://archive.debian.org/debian/pool/main/f/fonts-beng-extra/fonts-beng-extra_1.0-5_all.deb)
  （DEB SHA-256 `a909350b82912cf377d8e5cc803596b71b8beed87032788115c6766ac6f06082`）。
- 许可证证据：[逐文件 `debian/copyright`](https://sources.debian.org/data/main/f/fonts-beng-extra/1.0-5/debian/copyright)，
  SHA-256 `0906ca9525efa072ec67a37ed19c94cd0d37dea60c6707076cdfa66bdef7bc3c`，
  对六个文件分别声明 `GPL-2.0+`。
- 判定：**证据可 reviewed 为 `GPL-2.0-or-later`**，不得添加字体例外。
  仍需把版本化 Debian 证据和 DEB 摘要纳入可离线验证的镜像输入。

## `fonts-gujr-extra`

锁定 payload：

```text
padmaa.ttf  408c17220a90d7ce6855ac576f4d7f5fd9c6500add28834d00e7b63414c56248
Rekha.ttf   f73ac85b632fd16dd1b02ec8fc075ab1fd297122efcff44a092e119f9b466549
```

- metadata：Padmaa `0.7`，`fsType=0x0008`；Rekha `0.2`，`fsType=0x0000`。
  两者的 metadata 都说明字形/规则由 Cyberscape、IndicTrans 等权利人按 GPL
  发布，但只写 `GPL`，未在 payload 内给出版本。
- byte-identical：两个文件逐字节匹配
  [Debian Sources `fonts-gujr-extra/1.0-5`](https://sources.debian.org/src/fonts-gujr-extra/1.0-5/)
  和归档 DEB [`fonts-gujr-extra_1.0-5_all.deb`](https://archive.debian.org/debian/pool/main/f/fonts-gujr-extra/fonts-gujr-extra_1.0-5_all.deb)
  （DEB SHA-256 `a6aacb23516f768c934af03f09cc0f6f6e059582430a7e4b5e2b8ad73e84216f`）。
- 许可证证据：[上游 `Copyright`](https://sources.debian.org/data/main/f/fonts-gujr-extra/1.0-5/Copyright)
  SHA-256 `b96495a3dee941be0dba01d265b21030620417fc24d420d28f8ca7168f74709c`；
  [逐文件 `debian/copyright`](https://sources.debian.org/data/main/f/fonts-gujr-extra/1.0-5/debian/copyright)
  SHA-256 `3bb9e458484c1403105e72e6653fd5af0dffa91bdc60042bd395584b77f7bd60`。
  两者均将 payload 映射为 `GPL-2.0+`。
- 锁定树内的 `fonts-gujr-extra/LICENSE.txt` 实际属于 George Douros 的
  “Unicode Fonts for Ancient Scripts”，Git 实体 SHA-256
  `b27e84427e910eb7aa2996ca12ed5ea04c4b986ccc83e1ef6b59e8f36129b782`，
  与 Padmaa/Rekha 权利人和字体范围无关，必须排除。
- 判定：**证据可 reviewed 为 `GPL-2.0-or-later`**，不得使用仓内错误
  `LICENSE.txt`，也不得添加字体例外。仍需镜像并锁定正确外部证据。

## `kacst`

锁定 payload：

```text
KacstArt.ttf         efff71b8d1029058fdf2d9de322c4b3bbdc63cbebf31c755fe09e055d94aab85
KacstBook.ttf        ace66e3c454d4aa7e714af96db61ef3d3c724f701652ad5d1ae90530592de0f8
KacstDecorative.ttf  42a69e957246fd99945889f6cf66d9f5b721288da81589d8192134056a774ed8
KacstDigital.ttf     e9868ddeeeaa376512181de93e1809bc35683b760b2a0547523a730d89f3ca2e
KacstFarsi.ttf       f52d46fdcc43be640443dd20c738252f64115a7073ba58a88cad5b86c55ba1fb
KacstLetter.ttf      60a4d10163b488ab7d4bf6a37be0b1deface2367e1b2ac9f94f525837d7c5417
KacstNaskh.ttf       67f308cafe215397e3e03afbe121082410c058eae809efa5ed2d4bdc4546368e
KacstOffice.ttf      5a5c2ad17f2595f1f4f16e6c4083f3293c2e346ba7012ec72c5ece9e2e18668a
KacstPen.ttf         71e5c7e02121b81988e307859a743967d8e3b5fee3ad1c9246bffe2305cb7a02
KacstPoster.ttf      b551cd42e686f350e22470f764c4fbd6bf606fccef930f2a427e98b1fd3d009f
KacstQurn.ttf        404c21550f2dc1237c888ff33d2f0a7e296f6580c48b8e3311be689225ab42de
KacstScreen.ttf      e5a82b34030ba8c38a195b2ed1f87f3d1a6d4d15b9b215b93ab7d4652b4d6b67
KacstTitle.ttf       124652761601c37fe125246f47bd14b96a45b9bb07455d5c4801152907d701a5
KacstTitleL.ttf      804a5ade661ac85049bc594aaa5263370e374b957ba15964e0b2362e8e11e490
mry_KacstQurn.ttf    0c22089db14357c02f65ddcd6b860b46b36dd823944cf22013ed01e50bc23417
```

- metadata：十四个 KACST 字体为 `2.01`，每个都写明 KACST 将字体按 GPL
  捐赠并链接 GNU GPL；`mry_KacstQurn.ttf` 为 `1.003`，说明 KACST、URW 和
  Meor Ridzuan 的相关字形均按 GPL 捐赠。前十四个 `fsType=0x0000`，mry 为
  `0x0004`；这些嵌入位不改变许可证结论。
- byte-identical：十五个文件逐字节匹配
  [Debian Sources `fonts-kacst/2.01+mry-12`](https://sources.debian.org/src/fonts-kacst/2.01%2Bmry-12/)，
  也逐字节匹配 Ubuntu Bionic 官方发行包
  [`fonts-kacst_2.01+mry-14_all.deb`](https://archive.ubuntu.com/ubuntu/pool/main/f/fonts-kacst/fonts-kacst_2.01+mry-14_all.deb)，
  DEB SHA-256 `a39255b7b6c39bc1ee027111b091cdbd47fe9ac80bd99de8cf81331557e782d5`。
- 许可证证据：[完整 GPL v2 `kacst/LICENSE`](https://sources.debian.org/data/main/f/fonts-kacst/2.01%2Bmry-12/kacst/LICENSE)
  SHA-256 `296b69823ccb33e5785d7871e4dc05ac78426ae59873a258c5180556fe72782a`；
  [逐文件 `debian/copyright`](https://sources.debian.org/data/main/f/fonts-kacst/2.01%2Bmry-12/debian/copyright)
  SHA-256 `1f0d02a4efa1b7095e2cf8a2c2ad6c57dfabdf444c0b7abede69cb9ce6226c8b`，
  分别将 `kacst/*` 和 mry 字体声明为 `GPL-2`。
- Ubuntu 的签名
  [`2.01+mry-14.dsc`](https://archive.ubuntu.com/ubuntu/pool/main/f/fonts-kacst/fonts-kacst_2.01+mry-14.dsc)
  SHA-256 `ae9e7bde3d65d5a5fd690b3d3a0ed90a8bba0e5041d2837cc159f6551830e4e6`；
  其 main orig tar SHA-256
  `6f2899ce9622314ea426cf8d48849f1cf17302726d73cb683486d5fdf2a23338`，
  mry orig tar SHA-256
  `7ccea81dc721f0796738898bb3d587df1a1004d8e25e4266d56a835aa46a1efa`。
- 判定：**证据可 reviewed 为 `GPL-2.0-only`**。Debian copyright 末尾把
  common-license 路径误写成 `LGPL-2`，不能单独使用该路径；应同时锁定上述
  完整 GPL v2 实体和逐文件映射。

## `kacst-one`

锁定 payload：

```text
KacstOne-Bold.ttf  7435d251232017c6fe2ac1413f26f9d6a9d212927b395e3876e27bc4e552387b
KacstOne.ttf       bdd4d78a967018d658562a3a1eb705d07289b5c771978604f0e3526e2013dbac
```

- metadata：两者均为 `Version 5.0`，copyright 覆盖 KACST、FSF 和 Khaled
  Hosny；许可证字段说明 KACST 字形按 GPL 捐赠并链接 GNU GPL，
  `fsType=0x0000`。
- byte-identical：两个文件逐字节匹配 Ubuntu 官方发行包
  [`fonts-kacst-one_5.0+svn11846-9_all.deb`](https://archive.ubuntu.com/ubuntu/pool/main/f/fonts-kacst-one/fonts-kacst-one_5.0%2Bsvn11846-9_all.deb)，
  DEB SHA-256 `c2a7fdef3d7658c4f50941b976c9f2422b8e58496d8e72ae07310dd364fa63b5`。
- 权威 ref：[Ubuntu/Launchpad 源码版本 `5.0+svn11846-9`](https://launchpad.net/ubuntu/+source/fonts-kacst-one/5.0%2Bsvn11846-9)。
  其签名 DSC SHA-256
  `069ba26000cefa4beb80f189574cf4681cdd8a3bcbfcdbe946083a8e943327d3`，
  并将 orig tar 锁为
  `87fd3ee081edebb0fbb9eaa40de1dc0820956774dde37a1d55be201e09874d8e`，
  Debian tar 锁为
  `e8bb07a89f47bf2383f9c4f6a31ea1bd79a9c0e637a07a96a97fd2d135a5b0ce`。
- 许可证证据：DEB 内 `usr/share/doc/fonts-kacst-one/copyright` SHA-256
  `5d12ca7c5fba6bd2c8bbe9f0a079befa8311d98300345e48aaa9dde28a0257cc`，
  对 `Files: *` 声明 `GPL-2`；源码归档的完整 `LICENSE` SHA-256
  `296b69823ccb33e5785d7871e4dc05ac78426ae59873a258c5180556fe72782a`。
- 判定：**证据可 reviewed 为 `GPL-2.0-only`**。仍需在 bootstrap 阶段镜像
  exact DEB、签名 DSC 和源码许可证，build/verify 阶段只消费摘要锁定内容。

## `liberation`

锁定 payload：

```text
LiberationMono-Bold.ttf              1e81c74bfaf93ce724e3c2118f085c84ee9f9aa7a56bfe4e87d7746863c4ab95
LiberationMono-BoldItalic.ttf        319157f5d824ede8ce397e46d65d1fbd4d01c3699a903fff73c5a17ec120f5d9
LiberationMono-Italic.ttf            00b76b2717491709a2c7f8dfacfebeeee12cdce06fb8a95b0dd8836033a432af
LiberationMono-Regular.ttf           5738bfd34fac3e9454281b3ebdff6ba64f0558fac3dad4c7da22aae21a05fc1e
LiberationSans-Bold.ttf              e32256f280c7ffeb29f9b8da6ceb64781c440ccd683b5fcc9c22646ffec019c5
LiberationSans-BoldItalic.ttf        a3dbf57c98a0a6ec8fc7a10301f2f4440dbb171c90a3b5ab48b05622469bb9ce
LiberationSans-Italic.ttf            0f9b08355791c08e7e704063d56971f72b31fde0bffe63a57f5683779ff9db8b
LiberationSans-Regular.ttf           d44ef4341131f4f9bc7d336e0d5c479fe6ecf15a183e6b5a4e88289dd2d333d6
LiberationSansNarrow-Bold.ttf        5ff9217a6a7cd6cccdca8fd436e3d8a7bbb075e7f6c009f8809480dc5349e2e6
LiberationSansNarrow-BoldItalic.ttf  ceac79459f017d19275118fc27fbffb2924c2dd6645d362b0afece16026d98ec
LiberationSansNarrow-Italic.ttf      f1d1465feb4ab621b9eadc42a722b5895944debd0aab96ef197e9ae3ab609c55
LiberationSansNarrow-Regular.ttf     31de1a7adf5eb3e01a3d2319cae80ede2379a09cbbf692eb56f7024bfb0c8237
LiberationSerif-Bold.ttf             0755523e1bf3f40612a563c0f5f4ce2e97110a9f5900b15b3dd598185f138ecb
LiberationSerif-BoldItalic.ttf       a9ddeee9ca1ec9138d9fef5e6103f84e9113d1f1f34f97db61e1cd034150f722
LiberationSerif-Italic.ttf           758024be56a69ac7222e41ea441c4a3bc2fef8386c27506afa0e52473a5df19d
LiberationSerif-Regular.ttf          44c68d8acbf7314226592d30b50caf3832aaa81ab63b40f60cd11369618a613a
```

- metadata：十六个 payload 都是 `Version 1.07.4`，`fsType=0x0000`，并在
  `name` ID 13/14 中写明 `Licensed under the Liberation Fonts license`
  和 Fedora 的 `LiberationFontLicense` URL。非 Narrow 字体标明 Red Hat、
  Ascender/Steve Matteson；Narrow 字体标明 Oracle。
- 版本映射：Red Hat/Fedora 托管的官方
  [`liberation-fonts-1.07.4.tar.gz`](https://releases.pagure.org/liberation-fonts/liberation-fonts-1.07.4.tar.gz)
  SHA-256 `ad98b7498dc2992f7f0868f79b65ce4a720a3acdb63ab3f1f1cb6881117a5406`；
  其中 `License.txt` SHA-256
  `c40dd6adebad817defd68c7edad151d9c13d2ac3b4e1790ce2b727b024438b6d`。
  签名的 [Ubuntu/Launchpad `1.07.4-1` DSC](https://launchpad.net/ubuntu/+source/fonts-liberation/1.07.4-1)
  也锁定同一 orig tar 摘要。
- byte-identical：**原始字节否，但具备强版本映射**。官方预编译
  [`liberation-fonts-ttf-1.07.4.tar.gz`](https://releases.pagure.org/liberation-fonts/liberation-fonts-ttf-1.07.4.tar.gz)
  SHA-256 `61a7e2b6742a43c73e8762cdfeaf6dfcf9abdd2cfa0b099a9854d69bc4cfee5c`，
  其 TTF 与锁定 payload 不同。最强对照是 Debian Archive
  [`fonts-liberation_1.07.4-2_all.deb`](https://archive.debian.org/debian/pool/main/f/fonts-liberation/fonts-liberation_1.07.4-2_all.deb)，
  SHA-256 `b342d0382aaf8d64a61c347b6e83f84c1ad50aa4ed3df661ece9010fce3ee72a`。
  将 OpenType `head` 表的 `checksumAdjustment`、`created` 和 `modified`
  字段归零后，DEB 与锁定树的 16/16 字体全部逐表相同；原始差异仅位于这些
  构建字段。其签名
  [`1.07.4-2.dsc`](https://archive.debian.org/debian/pool/main/f/fonts-liberation/fonts-liberation_1.07.4-2.dsc)
  SHA-256 `d51db467a65d67ede5f6cace49946dd869f3ee3c8f264ee45e7b1c60eacdea5c`。
  绑定依据仍是精确结构比较和每个锁定 payload 自身的版本、权利人及许可证
  字段，不是邻近文件推断。
- 许可证：`License.txt` 是 GPL v2 加 Liberation 专用的文档嵌入例外、
  物理产品可替换源代码例外及商标条款。该文本不等同于 SPDX 标准
  `Font-exception-2.0`，应以完整提取文本建立项目 `LicenseRef`，不能缩写为
  普通字体例外或 `NOASSERTION`。
- 冲突信号：Debian 的
  [`debian/changelog`](https://sources.debian.org/data/main/f/fonts-liberation/1%3A1.07.4-2/debian/changelog)
  明确记载 2.x 改用 Croscore/OFL 是为解决长期许可证问题，并因许可证冲突不再
  包含 Liberation Sans Narrow。该记录没有逐文件裁定 1.07.4 的全部权利，但
  锁定组件恰好包含四个 Sans Narrow payload，不能只凭内嵌 URL 宣告闭环。
- 判定：**暂不可 reviewed**。技术版本映射已经充分，但必须以
  `CONFLICTING_TERMS` 继续失败关闭。只有显式法律/ADR 审核确认完整
  `License.txt` 对十六个 payload（特别是 Oracle Sans Narrow）的范围和附加
  条款均可接受后，才能用完整提取文本建立如
  `LicenseRef-Liberation-Fonts-1.07.4` 的项目标识；否则应替换或移除该组件。

## 后续落锁约束

1. 只把 `fonts-beng-extra`、`fonts-gujr-extra`、`kacst` 和 `kacst-one`
   作为候选 reviewed；`ASC.ttf` 以 `MISSING_EVIDENCE`、`liberation` 以
   `CONFLICTING_TERMS` 保持失败关闭。
2. 外部源码、DEB、DSC 和许可证必须先由 `bootstrap` 镜像到公开只读仓或
   内容寻址缓存，并在 source input 中绑定 URL/ref、大小和 SHA-256；正式
   build 不得联网。
3. 对每个 TTF 同时保存 Git blob、实体 SHA-256 和实际采用的许可证证据摘要。
   `liberation` 还要保存逐字体 `name` ID 5/13/14 记录。
4. 不得使用 `NOASSERTION`、仓内相邻许可证或 `fsType` 推断；不得把
   `fonts-gujr-extra/LICENSE.txt` 纳入许可闭包。

`fsType` 的字段语义参考 Microsoft 的
[OpenType OS/2 规范](https://learn.microsoft.com/en-us/typography/opentype/spec/os2#fstype)。
