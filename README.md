# S2iReactApp

The react app was created using `npx create-react-app my-app` and has not been changed except for renaming the folder `mv my-app src`.

In s2i the following shell scripts run the process:

* src/assemble Used by the first stage to `npm install && npm run build` and move the files needed at runtime to a location convenient for the second stage
* src/assemble-runtime Used by the second stage to move the built React app to the default location for nginx `/var/lib/nginx/html`
* src/run Used at runtime to start nginx and point it at our `nginx.conf`

The Docker image used for the first stage is built with `docker build -t reactapp.s2i.builder -f Dockerfile.builder .` and is an Alpine image with node installed on it.

The Docker image used for the second stage is built with `docker build -t reactapp.s2i.runtime -f Dockerfile.runtime .` and is an Alpine image with nginx installed on it.

The `DockerfileBuild` runs the `docker build` for the two images.

Once these images are built the app Image can be built with:
`s2i build src reactapp.s2i.builder reactapp --runtime-image reactapp.s2i.runtime --runtime-artifact /app`
The `./s2i/build` script runs this command.

To run the app use `docker run --rm --publish 8080:8080 reactapp` and browse to the app on http://localhost:8080

Note: It would be possible to use a single node image as the basis for this build, but that would leave development tools, source code and so on in the image. Nginx is also appreciably better a web server for static files than node or anything installable via npm. A description of how this two stage build works can be found at https://github.com/openshift/source-to-image/blob/master/docs/runtime_image.md