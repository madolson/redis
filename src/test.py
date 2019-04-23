_process_counts(name_generator=lambda statistic: _make_stats_name(name, method, statistic)
                , statistics=_retrieve_from( stats_entry
                                          , ('TPS', _tps)
                                            , ('failures', _failures)
                                            , ('content-length-in-bytes', _bytes_transferred))
                , stats_count_receiver=lambda n, v: stats_count_receiver(n, timestamp, v)
                , logger=logger)