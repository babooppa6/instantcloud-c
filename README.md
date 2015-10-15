# Instant Cloud API - C client

This repository contains sample C code for making API requests to the Gurobi Instant Cloud.

## Obtaining this repository

If you have git installed, you can obtain this repository, by cloning it, with the following command:

```
git clone https://github.com/Gurobi/instantcloud-c.git
```

If you don't have git installed, you can obtain this repository, by
clicking the Download Zip button in the right sidebar.

## Third-party libraries

The `instantcloud` program uses the [cURL](http://curl.haxx.se)
library for making HTTP request. We recommend installing the
appropriate cURL binary package for your platform. [This
page](http://curl.haxx.se/download.html) lists the available pacakges.
The cURL library itself has an MIT license, it can include various
different SSL packages which have different licenses. For more information
see this page on cURL [license mixing](http://curl.haxx.se/legal/licmix.html).

The `instantcloud` program uses the JSON parsing library [jsmn](http://zserge.com/jsmn.html),
which is licensed under the MIT license. See [this page](http://opensource.org/licenses/mit-license.php)
for more information on the jsmn license. The jsmn library is included directly in the source of `cloud.c`
and `cloud.h`.

The `instantcloud` program uses public domain code based on libcrypt for computing HMAC SHA1.
For more information see [this page](http://oauth.googlecode.com/svn/code/c/liboauth/src/sha1.c)


## Building the C client

If you are running under Linux or Mac OS X, issue the following command to build the C client:
```
make all
```

## Using instantcloud from the command-line

The `instantcloud` program can be used as a command-line client for the API. It provides
access to the four API endpoints: licenses, machines, launch, kill.

### List your licenses

Run the following command to list your licenses:

```
./instantcloud licenses --id INSERT_YOUR_ID_HERE --key INSERT_YOUR_KEY_HERE
```

You should see output like the following:
```
License Credit  Rate Plan       Expiration
95912   659.54  standard        2016-06-30
95913   44.10   nocharge        2016-06-30
```

### List your running machines

Run the following command to list your running machines

```
./instantcloud machines --id INSERT_YOUR_ID_HERE --key INSERT_YOUR_KEY_HERE
```

You should see output like the following:

```
Machine name:  ec2-54-85-186-203.compute-1.amazonaws.com
        license type:  light compute server
        state:  idle
        machine type:  c4.large
        region:  us-east-1
        idle shutdown:  60
        user password:  a446887d
        create time:  2015-10-14T20:27:01.224Z
        license id:  95912
        machine id:  xjZTbW9tdqbT32Cep
```


### Launch a machine

Run the following command to launch a machine

```
./instantcloud launch --id INSERT_YOUR_ID_HERE --key INSERT_YOUR_KEY_HERE -n 1 -m c4.large
```

You should see output similar to the following
```
Machines Launched
Machine name:  -
        license type:  light compute server
        state:  launching
        machine type:  c4.large
        region:  us-east-1
        idle shutdown:  60
        user password:  a446887d
        create time:  2015-10-14T20:27:01.224Z
        license id:  95912
        machine id:  xjZTbW9tdqbT32Cep
```


### Kill a machine

Run the following command to kill a machine

```
./instantcloud kill --id INSERT_YOUR_ID_HERE --key INSERT_YOUR_KEY_HERE xjZTbW9tdqbT32Cep
```

You should see output similar to the following

```
Machines Killed
Machine name:  ec2-54-85-186-203.compute-1.amazonaws.com
        license type:  light compute server
        state:  killing
        machine type:  c4.large
        region:  us-east-1
        idle shutdown:  60
        user password:  a446887d
        create time:  2015-10-14T20:27:01.224Z
        license id:  95856
        machine id:  xjZTbW9tdqbT32Cep

```
