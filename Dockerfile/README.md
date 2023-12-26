Build: `docker build -t runtimemobilesecurity .`

Run and access an iPhone from the container on Linux: `sudo docker run --rm -it --pid=host -v /var/run:/var/run -p 5491:5491 runtimemobilesecurity`
