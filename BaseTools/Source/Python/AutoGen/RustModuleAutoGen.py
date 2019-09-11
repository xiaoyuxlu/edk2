## @file
# Create rust module autogen obj
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
from __future__ import absolute_import
from AutoGen.AutoGen import AutoGen


class RustModuleAutoGen(AutoGen):
    def __init__(self, Workspace, MetaFile, Target, Toolchain, Arch, *args, **kwargs):
        self.Workspace = Workspace
        self.MetaFile = MetaFile
        self.Target = Target
        self.ToolChain = Toolchain
        self.Arch = Arch
        self._args = args
        self._kwargs = kwargs

    @property
    def MakeFileDir(self):
        return self.MetaFile.Dir

    @property
    def BuildTarget(self):
        return self.MetaFile.File

    def __repr__(self):
        return "%s [%s]" % (self.MetaFile, self.Arch)

    def __hash__(self):
        return hash((self.MetaFile, self.Arch))