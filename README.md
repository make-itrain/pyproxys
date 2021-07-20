# pyproxys
This package contains only one file, which is the whole source code for **a fully functional http proxy server**.

You can control proxy server authentication via the `auth_list` parameter of `HttpProxyServer` object's constructor. It takes a list of `(username, password)` tuples, 
which represent valid authentication credentials for your proxy server clients.

Just run the `__main__` function to get the idea. It'll start the proxy server on port `1111`, which you can access through `localhost`. 
If you'd like to make the proxy server accessible to the world outside, call `start` function with the `host` parameter set to `0.0.0.0`.
Now you'll be able to use your public ip address to access the proxy server.
Sometimes you'll need to configure the port forwarding rules on your router - but that's another story, google, if it doesn't work.

Tested on `Windows 10` using `Google Chrome` browser. Works all right.
