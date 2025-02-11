package bpftcp

// type bpftcpReceiver struct {
// 	statsColl *tcp.TcpStatsCollector

// 	mb       *metadata.MetricsBuilder
// 	mc       consumer.Metrics
// 	topStopC chan struct{}
// }

// var _ receiver.Metrics = (*bpftcpReceiver)(nil)

// func newBpfTcpReceiver(set receiver.Settings, mc consumer.Metrics) (*bpftcpReceiver, error) {
// 	r := &bpftcpReceiver{
// 		mc:       mc,
// 		mb:       metadata.NewMetricsBuilder(metadata.DefaultMetricsBuilderConfig(), set),
// 		topStopC: make(chan struct{}),
// 	}
// 	r.statsColl = tcp.NewTcpStatsCollector(
// 		slog.Default().With("collector", "tcpstats"),
// 		15*time.Second,
// 		func(key tcp.TcpconnlatTrafficKey, val tcp.TcpconnlatTrafficValue) {
// 			now := pcommon.NewTimestampFromTime(time.Now())
// 			// slog.Default().Info(fmt.Sprintf("tcp stats : %s", now.String()))
// 			isEmptyTcp6 := byteutil.EmptyIpv6(byteutil.Ipv6Str(key.SaddrV6))
// 			if val.Rx > 0 {
// 				var saddr string
// 				var daddr string
// 				if isEmptyTcp6 {
// 					saddr = byteutil.Ipv4Str(key.SaddrV4)
// 					daddr = byteutil.Ipv4Str(key.DaddrV4)
// 				} else {
// 					saddr = byteutil.Ipv6Str(key.SaddrV6)
// 					daddr = byteutil.Ipv6Str(key.DaddrV6)
// 				}
// 				name := byteutil.CCharSliceToStr(key.Name[:])
// 				r.mb.RecordBpfTCPRxDataPoint(now, int64(val.Rx), int64(key.Pid), name, saddr, daddr)
// 			}
// 			if val.Tx > 0 {
// 				var saddr string
// 				var daddr string
// 				if isEmptyTcp6 {
// 					saddr = byteutil.Ipv4Str(key.SaddrV4)
// 					daddr = byteutil.Ipv4Str(key.DaddrV4)
// 				} else {
// 					saddr = byteutil.Ipv6Str(key.SaddrV6)
// 					daddr = byteutil.Ipv6Str(key.DaddrV6)
// 				}
// 				name := byteutil.CCharSliceToStr(key.Name[:])
// 				r.mb.RecordBpfTCPTxDataPoint(now, int64(val.Tx), int64(key.Pid), name, saddr, daddr)
// 			}
// 		})

// 	if err := r.statsColl.Init(); err != nil {
// 		return nil, err
// 	}
// 	slog.Default().Info("tcp stats collector initialized")
// 	return r, nil
// }

// func (b *bpftcpReceiver) Start(ctx context.Context, _ component.Host) error {
// 	slog.Default().Info("starting collector....")
// 	if err := b.statsColl.Start(); err != nil {
// 		return err
// 	}

// 	go func() {
// 		t := time.NewTicker(15 * time.Second)
// 		defer t.Stop()
// 		for {
// 			select {
// 			case <-t.C:
// 				slog.Default().Info("scraping metrics")
// 				metrics := b.mb.Emit()
// 				if err := b.mc.ConsumeMetrics(ctx, metrics); err != nil {
// 					slog.Default().Error(err.Error())
// 				}
// 			case <-ctx.Done():
// 				slog.Default().Info("stopping bpftcp receiver ctx.Done()")
// 				return
// 			case <-b.topStopC:
// 				slog.Default().Info("stopping bpftcp receiver stopC")
// 				return
// 			}
// 		}
// 	}()
// 	slog.Default().Info("collector started")
// 	return nil
// }

// func (b *bpftcpReceiver) Shutdown(ctx context.Context) error {
// 	slog.Default().Info("shutting down collector....")
// 	b.statsColl.Shutdown()
// 	close(b.topStopC)
// 	return nil
// }
