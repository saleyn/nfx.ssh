﻿/*
 Copyright (c) 2005 Poderosa Project, All Rights Reserved.
 This file is a part of the Granados SSH Client Library that is subject to
 the license included in the distributed package.
 You may not use this file except in compliance with the license.

 $Id: ConnectionParameter.cs,v 1.5 2011/10/27 23:21:56 kzmi Exp $
*/

using System;
using System.Diagnostics;
using System.Collections;

namespace NFX.SSH {

    /// <summary>
    /// 
    /// </summary>
    /// <exclude/>
    public class ChannelCollection {
        private int _channel_sequence;
        private int _count;
        private Entry _first;

        public ChannelCollection() {
        }

        /// <summary>
        /// 
        /// </summary>
        /// <exclude/>
        public class Entry {
            private int _localID;
            private ISSHChannelEventReceiver _receiver;
            private SSHChannel _channel;
            private Entry _next;

            public int LocalID {
                get {
                    return _localID;
                }
            }
            public ISSHChannelEventReceiver Receiver {
                get {
                    return _receiver;
                }
            }
            public SSHChannel Channel {
                get {
                    return _channel;
                }
                set {
                    _channel = value;
                }
            }

            internal Entry Next {
                get {
                    return _next;
                }
                set {
                    _next = value;
                }
            }


            public Entry(SSHChannel ch, ISSHChannelEventReceiver r, int seq) {
                _channel = ch;
                _receiver = r;
                _localID = seq;
            }
        }

        public Entry FindChannelEntry(int id) {
            Entry e = _first;
            while (e != null) {
                if (e.LocalID == id)
                    return e;
                e = e.Next;
            }
            return null;
        }

        public Entry RegisterChannelEventReceiver(SSHChannel ch, ISSHChannelEventReceiver r) {
            lock (this) {
                Entry e = new Entry(ch, r, _channel_sequence++);

                if (_first == null)
                    _first = e;
                else {
                    e.Next = _first;
                    _first = e;
                }

                _count++;
                return e;
            }
        }

        internal void RegisterChannel(int local_id, SSHChannel ch) {
            FindChannelEntry(local_id).Channel = ch;
        }

        internal void UnregisterChannelEventReceiver(int id) {
            lock (this) {
                Entry e = _first;
                Entry prev = null;
                while (e != null) {

                    if (e.LocalID == id) {
                        if (prev == null)
                            _first = e.Next;
                        else {
                            Debug.Assert(prev.Next == e);
                            prev.Next = e.Next;
                        }
                        break;
                    }

                    prev = e;
                    e = e.Next;
                }

                _count--;
            }
        }

        public int Count {
            get {
                return _count;
            }
        }

    }
}
