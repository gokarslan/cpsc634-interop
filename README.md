# Internet Router Interoperability

[![Travis-CI Status](https://travis-ci.org/fno2010/internet-router-interop.svg?branch=master)][travis-ci]

This is a candidate repo for automatic [internet router
interoperability][cs634-project] test. To use it, please:

1. Create your internet router project following the format of the
   [example][ref-router].
2. Add your project as a submodule of this repo (under the `interop.p4app`
   directory).
3. Modify the `topo.json` file to configure your own switch.
4. Push your commit, then you can go to [Travic CI][travis-ci] to see the
   result of interoperability test.

The following sections describe some details about the implementation
guideline and configuration.

[cs634-project]: https://yale-build-a-router.github.io/documentation/internet-router/
[travis-ci]: https://travis-ci.org/fno2010/internet-router-interop
[ref-router]: https://github.com/fno2010/maclearning.p4app

## Create Mininet Switch Class Extending P4RuntimeSwitch

You should implement a python class extending `P4RuntimeSwitch`:

``` python
from p4_mininet import P4RuntimeSwitch

class MySwitch(P4RuntimeSwitch):
    def __init__(self, *opts, **kwargs):
        ...
        P4RuntimeSwitch.__init__(self, *opts, **kwargs)
```

The `__init__` method of this class should accept a `prog` argument for the
input P4 program at least.

> Note: This is the recommended way to implement your switch class. The
interoperability test program will rename the value of `prog` before it is
passed to your class to remove the potential naming conflict.
>
> You can also input your p4 program in your own way. But you should realize
the `prog` argument is reserved by the interoperability test program.

You should implement your control plane program and start it in the `start`
method of your switch class:

``` python
from p4_mininet import P4RuntimeSwitch

class MySwitch(P4RuntimeSwitch):
    ...

    def start(self, controllers):
        super(MySwitch, self).start(controllers)
        ...
        # start your own controller here
        self.controller = YourController()
        self.controller.start()
```

It is recommended to assign your control plane program instance to
`self.controller` attribute of your switch class. And your control plane
program should implement a `join` method to terminate a running session. The
interoperability test program will try to call `self.controller.join()` of
each running switch to stop the running controller session before the test
stopped.

Your control plane program should listen to a port of your switch. You should
provide some approach to allow mininet to specify this port number from the
`__init__` method of your switch class.

You can take a look at a [reference
implementation][ref-router] to better
understand how to implement your own switch class.

> **IMPORTANT:** you should create a `__init__.py` file (which can be empty)
in the top-level directory of your repo to make it a valid python module. The
interoperability test program will try to import it as a python module.

## Add Submodule to the Interop Repo

Then you can add your own repo to this interop repo as a submodule:

``` sh
# Clone this interop repo first
git clone https://github.com/fno2010/internet-router-interop
cd internet-router-interop

# Clone your own repo under the interop.p4app dir
pushd interop.p4app
# git clone <url_to_your_repo> <your_name>
git clone https://github.com/fno2010/pwospf jensen
popd

# Commit the submodule to the interop repo
# git submodule add <url_to_your_repo> interop.p4app/<your_name>
git submodule add https://github.com/fno2010/pwospf interop.p4app/jensen
git commit -m "Add jensen's pwospf router"
```

> Note: You should rename your repo to some custom name to avoid naming
conflict. The name should be a valid python module name (a valid identifier).

When you update your own router repo, you can go to the interop repo and pull
your submodule to the latest one.

``` sh
push interop.p4app/jensen
git pull
pop

git add .
git commit -m "Update jensen's pwospf router to v2"
```

## Configure Your Router in JSON

Then you should modify the `topo.json` file to configure some switch node to
use your own switch class.

``` json
{
  "switches": {
    "sw1": {
      "class": "example.maclearning.MacLearningSwitch",
      "prog": "/p4app/example/l2switch.p4",
      "enable_ctrl": true,
      "ctrl_args": {
        "ctrl_port": 1,
        "start_wait": 0.5
      }
    },
    ...
  },
  "hosts": { ... },
  "links": [ ... ]
}
```

The value of `class` should be `<your_module_name>.<your_class_name>` of your
own switch class. In this example, we assume your repo is renamed to
`example`, and you implement your class `MacLearningSwitch` in a python file
called `maclearning.py`.

The value of `prog` should be the path to your P4 program. If the path is
relative, the current working directory should be the `interop.p4app`
directory. If the path is absolute, you should replace the current working
directory to `/p4app`.

**If you want to use a control plane program, you MUST set `enable_ctrl` as
`true`.** It will ask the interoperability test program create a controller
interface for the switch automatically. The port number of this interface
will be `1`. So you should use your own approach to notify your own control
plane session this port number. In our reference implementation, we use
`ctrl_args` to pass the related arguments. It is not mandatory for your own
implementation.

All the attributes of this switch object in this JSON will be passed to the
`__init__` method of your own switch class. So you can do some customization
by yourself.

## Track the Interop Test in Travic CI

You don't have to do anything. Just push all your changes to the interop
repo. It will trigger the Travis CI to do test automatically.

``` sh
git add .
git commit -m "Add jensen's config to interop"
git push
```

Now go to [Travic CI][travis-ci] to see the result.
