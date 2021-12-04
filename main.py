from handler import Handler
from config_reader import Reader
import time
from multiprocessing import Pool
class Main:

    check_handler = Handler()
    def handle_benchmark(self):
        # This is for benchmark verification
        def benchmark_pretreat():
            reader = Reader()
            benchmarks = reader.benchmark_walker()
            for file in benchmarks:
                yield file, reader.read_and_translate(file)
        
        index = 0 
        for file, bench in benchmark_pretreat():
            print(index)
            self.check_bench(file, bench)
            index += 1
            
    def handle_benchmark_multi(self):
        # This is for benchmark verification
        def benchmark_pretreat():
            reader = Reader()
            benchmarks = reader.benchmark_walker()
            for file in benchmarks:
                yield file, reader.read_and_translate(file)
        
        index = 0 
        with Pool(1) as p:
            p.map(self.check_bench(benchmark_pretreat()))
        # for file, bench in benchmark_pretreat():
        #     print(index)
        #     self.check_bench(file, bench)
        #     index += 1
    def output_result(self, string):
        with open('result.txt', 'a') as f:
            f.write(string)
            f.write('\n')
            f.close()

    def check_bench(self, file, bench):
        print("Doing: {}".format(file))
        check_type = bench[0]
        if check_type == 0:
            result = self.check_handler.check_complete_intersection_with_topics(bench[3], bench[2], with_action=True)
        elif check_type == 2:
            result = self.check_handler.check_complete_expected_with_topics(bench[3], bench[1], bench[2])
        else:
            result = self.check_handler.check_complete_intersection_with_policy(bench[1], bench[2]) 
        if file.find('error') >= 0 and result:
            self.output_result('{}\t{}'.format(file,'Good'))
        elif file.find('error') < 0 and not result:
            self.output_result('{}\t{}'.format(file,'Good'))
        elif file.find('error') >= 0 and not result:
            self.output_result('{}\t{}'.format(file, 'False Negative'))
            print(file, result)
        elif file.find('error') <= 0 and result:
            self.output_result('{}\t{}'.format(file, 'False Positive'))
            print(file, result)
        # print(result)

def main():
    time1 = time.time()
    Main().handle_benchmark()
    time2 = time.time()
    print(time1)
    print(time2)
    print(time2 - time1)

if __name__ == '__main__':
    main()