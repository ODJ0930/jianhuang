本程序仅用于网站上下传测试，请勿用于非法用途
建议使用docker版本：https://github.com/ODJ0930/jianhuang-docker
docker一键部署：docker run -d -p 9111:3000 diead/jh:v0

使用方法很简单，先安装nodejs

一键脚本：<br>source <(curl -L https://nodejs-install.netlify.app/install.sh)

然后创建文件目录:
<br>mkdir website-tester<br>
cd website-tester

初始化npm并安装依赖:
<br>npm init -y<br>
npm install express socket.io

然后创建一个二级文件夹，名称为：public

最后把node.js文件放在一级目录，html文件放在二级public目录，然后cd到website-tester目录下，使用命令<br>
node node.js
就可以使用了

默认是3000端口，需要改动自己改一下
