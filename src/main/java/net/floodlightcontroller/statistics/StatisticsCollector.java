package net.floodlightcontroller.statistics;

import java.lang.Thread.State;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.ver13.OFMeterSerializerVer13;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.primitives.UnsignedLong;
import com.google.common.util.concurrent.ListenableFuture;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.statistics.web.SwitchStatisticsWebRoutable;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.topology.NodePortTuple;

public class StatisticsCollector implements IFloodlightModule, IStatisticsService {

	private static Logger log = LoggerFactory.getLogger(StatisticsCollector.class);

	private static IOFSwitchService switchService;
	private static IThreadPoolService threadPoolService;
	private static IRestApiService restApiService;

	private static boolean isEnabled = false;

	private static int portStatsInterval = 10; /* could be set by REST API, so not final */
	private static ScheduledFuture<?> portStatsCollector;


	private static final Logger logFlowStatsCollector = LoggerFactory.getLogger(FlowStatsCollector.class);
	private static final int flowStatsInterval = 10;
	private static ScheduledFuture<?> flowStatsCollector;


	private static final long BITS_PER_BYTE = 8;
	private static final long MILLIS_PER_SEC = 1000;

	private static final String INTERVAL_PORT_STATS_STR = "collectionIntervalPortStatsSeconds";
	private static final String ENABLED_STR = "enable";

	private static final HashMap<NodePortTuple, SwitchPortBandwidth> portStats = new HashMap<NodePortTuple, SwitchPortBandwidth>();
	private static final HashMap<NodePortTuple, SwitchPortBandwidth> tentativePortStats = new HashMap<NodePortTuple, SwitchPortBandwidth>();

	private static final String THRESHOLD_TX_PORT_STR = "PortTxThreshold";
	private static final String THRESHOLD_RX_PORT_STR = "PortRxThreshold";

	private static int portTxThreshold = 10;
	private static int portRxThreshold = 10;

	/**
	 * Run periodically to collect all port statistics. This only collects
	 * bandwidth stats right now, but it could be expanded to record other
	 * information as well. The difference between the most recent and the
	 * current RX/TX bytes is used to determine the "elapsed" bytes. A
	 * timestamp is saved each time stats results are saved to compute the
	 * bits per second over the elapsed time. There isn't a better way to
	 * compute the precise bandwidth unless the switch were to include a
	 * timestamp in the stats reply message, which would be nice but isn't
	 * likely to happen. It would be even better if the switch recorded
	 * bandwidth and reported bandwidth directly.
	 *
	 * Stats are not reported unless at least two iterations have occurred
	 * for a single switch's reply. This must happen to compare the byte
	 * counts and to get an elapsed time.
	 *
	 * @author Ryan Izard, ryan.izard@bigswitch.com, rizard@g.clemson.edu
	 *
	 */



	public class FlowStatsCollector implements Runnable {

		public void run() {
			Map<DatapathId, List<OFStatsReply>> replies = getSwitchStatistics(switchService.getAllSwitchDpids(), OFStatsType.FLOW);
			for (Entry<DatapathId, List<OFStatsReply>> e : replies.entrySet()) {
				for (OFStatsReply r : e.getValue()) { // dentro de un switch
					OFFlowStatsReply fsr = (OFFlowStatsReply) r;
					log.info("Flow entries switch: "+e.getKey());
					int i = 0;

					HashMap<IPv4Address, Integer> srcIPTable = new HashMap<>();
					HashMap<IPv4Address, Integer> dstIPTable = new HashMap<>();
					HashMap<OFPort, Integer> inPortTable = new HashMap<>();

					for (OFFlowStatsEntry fse : fsr.getEntries()) {
						log.info("\t"+i+")"+
								" PacketsCount: "+fse.getPacketCount().getValue()+
								" BytesCount: "+fse.getByteCount().getValue()+
								" InPort: "+fse.getMatch().get(MatchField.IN_PORT)+
								" SrcIP: "+fse.getMatch().get(MatchField.IPV4_SRC));

						i++;

						// consierando que existen flows ya insertados en cada switch:
						// la cantidad de matches (packetCount) en un flow indica la cantidad de veces que se repiten cada parámetro (src_port, dst_port, src_ip, dst_ip)
						// cada flow entry crea un conjunto de filas nuevas en la tabla de un parámetro
						// deben existir tablas para cada parámetro

						calculateEntropy(fse);
					}
				}
			}
		}
	}

	private void calculateEntropy(OFFlowStatsEntry flowStats){
		long count = flowStats.getPacketCount().getValue();
		Match match = flowStats.getMatch();

		IPv4Address srcIP = match.get(MatchField.IPV4_DST);
		IPv4Address dstIP = match.get(MatchField.IPV4_DST);
		OFPort inPort = match.get(MatchField.IN_PORT);
		TransportPort srcPort = match.get(MatchField.TCP_DST);
		TransportPort dstPort = match.get(MatchField.TCP_DST);
	}

	private class PortStatsCollector implements Runnable {

		@Override
		public void run() {
			Map<DatapathId, List<OFStatsReply>> replies = getSwitchStatistics(switchService.getAllSwitchDpids(), OFStatsType.PORT);
			for (Entry<DatapathId, List<OFStatsReply>> e : replies.entrySet()) {
				for (OFStatsReply r : e.getValue()) {
					OFPortStatsReply psr = (OFPortStatsReply) r;
					for (OFPortStatsEntry pse : psr.getEntries()) {
						NodePortTuple npt = new NodePortTuple(e.getKey(), pse.getPortNo());
						SwitchPortBandwidth spb;
						if (portStats.containsKey(npt) || tentativePortStats.containsKey(npt)) {
							if (portStats.containsKey(npt)) { /* update */
								spb = portStats.get(npt);
							} else if (tentativePortStats.containsKey(npt)) { /* finish */
								spb = tentativePortStats.get(npt);
								tentativePortStats.remove(npt);
							} else {
								log.error("Inconsistent state between tentative and official port stats lists.");
								return;
							}

							/* Get counted bytes over the elapsed period. Check for counter overflow. */
							U64 rxBytesCounted;
							U64 txBytesCounted;
							if (spb.getPriorByteValueRx().compareTo(pse.getRxBytes()) > 0) { /* overflow */
								U64 upper = U64.NO_MASK.subtract(spb.getPriorByteValueRx());
								U64 lower = pse.getRxBytes();
								rxBytesCounted = upper.add(lower);
							} else {
								rxBytesCounted = pse.getRxBytes().subtract(spb.getPriorByteValueRx());
							}
							if (spb.getPriorByteValueTx().compareTo(pse.getTxBytes()) > 0) { /* overflow */
								U64 upper = U64.NO_MASK.subtract(spb.getPriorByteValueTx());
								U64 lower = pse.getTxBytes();
								txBytesCounted = upper.add(lower);
							} else {
								txBytesCounted = pse.getTxBytes().subtract(spb.getPriorByteValueTx());
							}
							long timeDifSec = (System.currentTimeMillis() - spb.getUpdateTime()) / MILLIS_PER_SEC;
							portStats.put(npt, SwitchPortBandwidth.of(npt.getNodeId(), npt.getPortId(),
									U64.ofRaw((rxBytesCounted.getValue() * BITS_PER_BYTE) / timeDifSec),
									U64.ofRaw((txBytesCounted.getValue() * BITS_PER_BYTE) / timeDifSec),
									pse.getRxBytes(), pse.getTxBytes())
							);

							// no mostrando ancho de banda para testeo :v
							/*
							long txBandwidth = (rxBytesCounted.getValue() * BITS_PER_BYTE) / timeDifSec;
							long rxBandwidth = (txBytesCounted.getValue() * BITS_PER_BYTE) / timeDifSec;

							if (txBandwidth > portTxThreshold) {
								log.info("El ancho de banda de TX en el puerto {} excede el umbral: {}", npt, portTxThreshold);
							}
							if (rxBandwidth > portRxThreshold) {
								log.info("El ancho de banda de RX en el puerto {} excede el umbral: {}", npt, portRxThreshold);
							}

							 */
						} else { /* initialize */
							tentativePortStats.put(npt, SwitchPortBandwidth.of(npt.getNodeId(), npt.getPortId(), U64.ZERO, U64.ZERO, pse.getRxBytes(), pse.getTxBytes()));
						}
					}
				}
			}
		}
	}

	/**
	 * Single thread for collecting switch statistics and
	 * containing the reply.
	 *
	 * @author Ryan Izard, ryan.izard@bigswitch.com, rizard@g.clemson.edu
	 *
	 */
	private class GetStatisticsThread extends Thread {
		private List<OFStatsReply> statsReply;
		private DatapathId switchId;
		private OFStatsType statType;

		public GetStatisticsThread(DatapathId switchId, OFStatsType statType) {
			this.switchId = switchId;
			this.statType = statType;
			this.statsReply = null;
		}

		public List<OFStatsReply> getStatisticsReply() {
			return statsReply;
		}

		public DatapathId getSwitchId() {
			return switchId;
		}

		@Override
		public void run() {
			statsReply = getSwitchStatistics(switchId, statType);
		}
	}

	/*
	 * IFloodlightModule implementation
	 */

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IStatisticsService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m =
				new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		m.put(IStatisticsService.class, this);
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IOFSwitchService.class);
		l.add(IThreadPoolService.class);
		l.add(IRestApiService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		switchService = context.getServiceImpl(IOFSwitchService.class);
		threadPoolService = context.getServiceImpl(IThreadPoolService.class);
		restApiService = context.getServiceImpl(IRestApiService.class);
		log = LoggerFactory.getLogger(StatisticsCollector.class);

		Map<String, String> config = context.getConfigParams(this);
		if (config.containsKey(ENABLED_STR)) {
			try {
				isEnabled = Boolean.parseBoolean(config.get(ENABLED_STR).trim());
			} catch (Exception e) {
				log.error("Could not parse '{}'. Using default of {}", ENABLED_STR, isEnabled);
			}
		}
		log.info("Statistics collection {}", isEnabled ? "enabled" : "disabled");

		if (config.containsKey(INTERVAL_PORT_STATS_STR)) {
			try {
				portStatsInterval = Integer.parseInt(config.get(INTERVAL_PORT_STATS_STR).trim());
			} catch (Exception e) {
				log.error("Could not parse '{}'. Using default of {}", INTERVAL_PORT_STATS_STR, portStatsInterval);
			}
		}
		log.info("Port statistics collection interval set to {}s", portStatsInterval);


		if (config.containsKey(THRESHOLD_TX_PORT_STR)) {
			try {
				portTxThreshold = Integer.parseInt(config.get("PortTxThreshold").trim());
			} catch (Exception e) {
				log.error("Could not parse 'PortTxThreshold'. Using default value of {}", portTxThreshold);
			}
		}

		if (config.containsKey(THRESHOLD_RX_PORT_STR)) {
			try {
				portRxThreshold = Integer.parseInt(config.get("PortRxThreshold").trim());
			} catch (Exception e) {
				log.error("Could not parse 'PortRxThreshold'. Using default value of {}", portRxThreshold);
			}
		}
		log.info("PortTxThreshold set to: {}", portTxThreshold);
		log.info("PortRxThreshold set to: {}", portRxThreshold);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		restApiService.addRestletRoutable(new SwitchStatisticsWebRoutable());
		if (isEnabled) {
			startStatisticsCollection();
		}
	}

	/*
	 * IStatisticsService implementation
	 */

	@Override
	public SwitchPortBandwidth getBandwidthConsumption(DatapathId dpid, OFPort p) {
		return portStats.get(new NodePortTuple(dpid, p));
	}


	@Override
	public Map<NodePortTuple, SwitchPortBandwidth> getBandwidthConsumption() {
		return Collections.unmodifiableMap(portStats);
	}

	@Override
	public synchronized void collectStatistics(boolean collect) {
		if (collect && !isEnabled) {
			startStatisticsCollection();
			isEnabled = true;
		} else if (!collect && isEnabled) {
			stopStatisticsCollection();
			isEnabled = false;
		}
		/* otherwise, state is not changing; no-op */
	}

	/*
	 * Helper functions
	 */

	/**
	 * Start all stats threads.
	 */
	private void startStatisticsCollection() {
		portStatsCollector = threadPoolService.getScheduledExecutor().scheduleAtFixedRate(new PortStatsCollector(), portStatsInterval, portStatsInterval, TimeUnit.SECONDS);
		tentativePortStats.clear(); /* must clear out, otherwise might have huge BW result if present and wait a long time before re-enabling stats */
		log.warn("Statistics collection thread(s) started");

		flowStatsCollector = threadPoolService.getScheduledExecutor()
				.scheduleAtFixedRate(new FlowStatsCollector(), flowStatsInterval, flowStatsInterval, TimeUnit.SECONDS);
		log.info("Flow statistics collection thread started");
	}

	/**
	 * Stop all stats threads.
	 */
	private void stopStatisticsCollection() {
		if (!portStatsCollector.cancel(false)) {
			log.error("Could not cancel port stats thread");
		} else {
			log.warn("Statistics collection thread(s) stopped");
		}

		if (!flowStatsCollector.cancel(false)) {
			log.error("Could not cancel flow stats thread");
		} else {
			log.warn("Statistics collection thread(s) stopped");
		}
	}

	/**
	 * Retrieve the statistics from all switches in parallel.
	 * @param dpids
	 * @param statsType
	 * @return
	 */
	private Map<DatapathId, List<OFStatsReply>> getSwitchStatistics(Set<DatapathId> dpids, OFStatsType statsType) {
		HashMap<DatapathId, List<OFStatsReply>> model = new HashMap<DatapathId, List<OFStatsReply>>();

		List<GetStatisticsThread> activeThreads = new ArrayList<GetStatisticsThread>(dpids.size());
		List<GetStatisticsThread> pendingRemovalThreads = new ArrayList<GetStatisticsThread>();
		GetStatisticsThread t;
		for (DatapathId d : dpids) {
			t = new GetStatisticsThread(d, statsType);
			activeThreads.add(t);
			t.start();
		}

		/* Join all the threads after the timeout. Set a hard timeout
		 * of 12 seconds for the threads to finish. If the thread has not
		 * finished the switch has not replied yet and therefore we won't
		 * add the switch's stats to the reply.
		 */
		for (int iSleepCycles = 0; iSleepCycles < portStatsInterval; iSleepCycles++) {
			for (GetStatisticsThread curThread : activeThreads) {
				if (curThread.getState() == State.TERMINATED) {
					model.put(curThread.getSwitchId(), curThread.getStatisticsReply());
					pendingRemovalThreads.add(curThread);
				}
			}

			/* remove the threads that have completed the queries to the switches */
			for (GetStatisticsThread curThread : pendingRemovalThreads) {
				activeThreads.remove(curThread);
			}

			/* clear the list so we don't try to double remove them */
			pendingRemovalThreads.clear();

			/* if we are done finish early */
			if (activeThreads.isEmpty()) {
				break;
			}

			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				log.error("Interrupted while waiting for statistics", e);
			}
		}

		return model;
	}

	/**
	 * Get statistics from a switch.
	 * @param switchId
	 * @param statsType
	 * @return
	 */
	@SuppressWarnings("unchecked")
	protected List<OFStatsReply> getSwitchStatistics(DatapathId switchId, OFStatsType statsType) {
		IOFSwitch sw = switchService.getSwitch(switchId);
		ListenableFuture<?> future;
		List<OFStatsReply> values = null;
		Match match;
		if (sw != null) {
			OFStatsRequest<?> req = null;
			switch (statsType) {
				case FLOW:
					match = sw.getOFFactory().buildMatch().build();
					req = sw.getOFFactory().buildFlowStatsRequest()
							.setMatch(match)
							.setOutPort(OFPort.ANY)
							.setTableId(TableId.ALL)
							.build();
					break;
				case AGGREGATE:
					match = sw.getOFFactory().buildMatch().build();
					req = sw.getOFFactory().buildAggregateStatsRequest()
							.setMatch(match)
							.setOutPort(OFPort.ANY)
							.setTableId(TableId.ALL)
							.build();
					break;
				case PORT:
					req = sw.getOFFactory().buildPortStatsRequest()
							.setPortNo(OFPort.ANY)
							.build();
					break;
				case QUEUE:
					req = sw.getOFFactory().buildQueueStatsRequest()
							.setPortNo(OFPort.ANY)
							.setQueueId(UnsignedLong.MAX_VALUE.longValue())
							.build();
					break;
				case DESC:
					req = sw.getOFFactory().buildDescStatsRequest()
							.build();
					break;
				case GROUP:
					if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) > 0) {
						req = sw.getOFFactory().buildGroupStatsRequest()
								.build();
					}
					break;

				case METER:
					if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_13) >= 0) {
						req = sw.getOFFactory().buildMeterStatsRequest()
								.setMeterId(OFMeterSerializerVer13.ALL_VAL)
								.build();
					}
					break;

				case GROUP_DESC:
					if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) > 0) {
						req = sw.getOFFactory().buildGroupDescStatsRequest()
								.build();
					}
					break;

				case GROUP_FEATURES:
					if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) > 0) {
						req = sw.getOFFactory().buildGroupFeaturesStatsRequest()
								.build();
					}
					break;

				case METER_CONFIG:
					if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_13) >= 0) {
						req = sw.getOFFactory().buildMeterConfigStatsRequest()
								.build();
					}
					break;

				case METER_FEATURES:
					if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_13) >= 0) {
						req = sw.getOFFactory().buildMeterFeaturesStatsRequest()
								.build();
					}
					break;

				case TABLE:
					if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) > 0) {
						req = sw.getOFFactory().buildTableStatsRequest()
								.build();
					}
					break;

				case TABLE_FEATURES:
					if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_10) > 0) {
						req = sw.getOFFactory().buildTableFeaturesStatsRequest()
								.build();
					}
					break;
				case PORT_DESC:
					if (sw.getOFFactory().getVersion().compareTo(OFVersion.OF_13) >= 0) {
						req = sw.getOFFactory().buildPortDescStatsRequest()
								.build();
					}
					break;
				case EXPERIMENTER:
				default:
					log.error("Stats Request Type {} not implemented yet", statsType.name());
					break;
			}

			try {
				if (req != null) {
					future = sw.writeStatsRequest(req);
					values = (List<OFStatsReply>) future.get(portStatsInterval / 2, TimeUnit.SECONDS);
				}
			} catch (Exception e) {
				log.error("Failure retrieving statistics from switch {}. {}", sw, e);
			}
		}
		return values;
	}
}