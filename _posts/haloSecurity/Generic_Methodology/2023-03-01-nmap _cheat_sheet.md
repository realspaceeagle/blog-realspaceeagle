---
layout: post
title:  "nmap cheat sheet "
author: haran
categories: [nmap]
image: haloSecurity/Generic_Methodology/nmap.png
beforetoc: "nmap  scripts and explanations for better reconnaissance"
toc: true
---

![nmap]({{ site.baseurl }}/_posts/haloSecurity/Generic_Methodology/nmap.png)


```console?Prompt$
sudo nmap -sC -sV -oA seventeen 10.10.11.165
```


- -sC => default scipts
- -sV => default versions
- -oA => output all the files